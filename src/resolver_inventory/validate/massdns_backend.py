"""MassDNS backend for long-lived plain-DNS probing via streaming pipes."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import tempfile
from collections import defaultdict, deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from resolver_inventory.models import ProbeResult
from resolver_inventory.settings import DnsBackendConfig
from resolver_inventory.util.logging import get_logger
from resolver_inventory.validate.base import fail_probe, normalize_expected_answers
from resolver_inventory.validate.dns_plain import (
    evaluate_nxdomain_probe_result,
    evaluate_positive_probe_result,
)
from resolver_inventory.validate.plain_dns_backend import (
    PlainDnsExecutionCallback,
    PlainDnsProbeExecution,
    PlainDnsProbeSpec,
    run_python_plain_dns_batch,
)

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class MassDnsParsedResult:
    resolver: str | None
    qname: str
    rdtype: str
    rcode: str | None = None
    answers: list[str] | None = None
    latency_ms: float | None = None
    terminal_error: str | None = None


@dataclass(frozen=True, slots=True)
class MassDnsSessionMetrics:
    stdout_lines: int = 0
    stderr_lines: int = 0
    parsed_results: int = 0
    unmatched_results: int = 0
    terminal_failures_matched: int = 0
    probes_sent: int = 0
    exit_code: int = 0
    restarts: int = 0


MassDnsBatchMetrics = MassDnsSessionMetrics


@dataclass(slots=True)
class _MassDnsWorker:
    proc: asyncio.subprocess.Process
    resolver_path: Path
    stderr_task: asyncio.Task[int]


PlainDnsSpecSource = Callable[[], Iterable[PlainDnsProbeSpec]]


def group_probe_specs_for_massdns(
    specs: list[PlainDnsProbeSpec],
    *,
    batch_max_queries: int,
) -> list[list[PlainDnsProbeSpec]]:
    by_rdtype: dict[str, list[PlainDnsProbeSpec]] = defaultdict(list)
    for spec in specs:
        by_rdtype[spec.rdtype.upper()].append(spec)

    batches: list[list[PlainDnsProbeSpec]] = []
    max_queries = max(1, batch_max_queries)
    for rdtype in sorted(by_rdtype):
        group = by_rdtype[rdtype]
        for start in range(0, len(group), max_queries):
            batches.append(group[start : start + max_queries])
    return batches


def build_massdns_command(
    *,
    config: DnsBackendConfig,
    rdtype: str,
    resolver_file: Path,
) -> list[str]:
    interval_ms = max(1, config.interval_ms)
    cmd = [
        config.massdns_bin,
        "--extended-input",
        "-o",
        "Je",
        "-t",
        rdtype,
        "-s",
        str(config.hashmap_size),
        "--processes",
        str(config.processes),
        "--socket-count",
        str(config.socket_count),
        "--interval",
        str(interval_ms),
        "-r",
        str(resolver_file),
    ]
    if config.flush:
        cmd.append("--flush")
    if config.predictable:
        cmd.append("--predictable")
    if config.extra_args:
        cmd.extend(config.extra_args)
    return cmd


def build_manifest_line(spec: PlainDnsProbeSpec) -> str:
    return f"{spec.qname} {spec.host}:{spec.port}\n"


def _result_identity_key(resolver: str, qname: str, rdtype: str) -> tuple[str, str, str]:
    q = qname.lower().rstrip(".") + "."
    rdt = rdtype.upper()
    if ":" in resolver and resolver.count(":") == 1:
        host, port = resolver.rsplit(":", 1)
        return host, str(int(port)), q + rdt
    return resolver, "53", q + rdt


def _spec_identity_key(spec: PlainDnsProbeSpec) -> tuple[str, str, str]:
    q = spec.qname.lower().rstrip(".") + "."
    return spec.host, str(spec.port), q + spec.rdtype.upper()


def _name_type_identity_key(qname: str, rdtype: str) -> tuple[str, str]:
    q = qname.lower().rstrip(".") + "."
    return q, rdtype.upper()


def _extract_answers(record: dict[str, object], rdtype: str) -> list[str]:
    raw_answers = record.get("answers")
    if raw_answers is None and isinstance(record.get("data"), dict):
        raw_answers = record["data"].get("answers")  # type: ignore[index]

    answers: list[str] = []
    if isinstance(raw_answers, list):
        for answer in raw_answers:
            if isinstance(answer, str):
                answers.append(answer.split()[-1])
                continue
            if not isinstance(answer, dict):
                continue
            a_type = str(answer.get("type", rdtype)).upper()
            if a_type != rdtype.upper():
                continue
            value = answer.get("data") or answer.get("answer") or answer.get("value")
            if value is None:
                continue
            answers.append(str(value))
    return normalize_expected_answers(answers, rdtype)


def parse_massdns_ndjson_line(
    line: str,
    *,
    default_rdtype: str | None = None,
) -> MassDnsParsedResult:
    decoded = json.loads(line)
    if not isinstance(decoded, dict):
        raise ValueError("massdns output line is not a JSON object")

    qname = str(decoded.get("name") or decoded.get("qname") or "")
    resolver_raw = decoded.get("resolver") or decoded.get("resolver_ip")
    resolver = None if resolver_raw in (None, "") else str(resolver_raw)
    rdtype = str(decoded.get("type") or decoded.get("qtype") or default_rdtype or "")
    if not qname or not rdtype:
        raise ValueError(
            "massdns output line missing required fields: "
            f"has_qname={bool(qname)} has_resolver={bool(resolver)} has_rdtype={bool(rdtype)}"
        )

    rcode = decoded.get("rcode") or decoded.get("status")
    if rcode is None and isinstance(decoded.get("data"), dict):
        rcode = decoded["data"].get("rcode")  # type: ignore[index]

    terminal_error = decoded.get("error") or decoded.get("failure")
    latency_raw = decoded.get("latency_ms") or decoded.get("rt")
    latency_ms: float | None = None
    if isinstance(latency_raw, (int, float)):
        latency_ms = float(latency_raw)

    return MassDnsParsedResult(
        resolver=resolver,
        qname=qname,
        rdtype=rdtype,
        rcode=None if rcode is None else str(rcode).upper(),
        answers=_extract_answers(decoded, rdtype),
        latency_ms=latency_ms,
        terminal_error=None if terminal_error is None else str(terminal_error),
    )


async def parse_massdns_ndjson_stream(
    stdout: asyncio.StreamReader,
    pending_by_key: (
        dict[tuple[str, str, str], deque[PlainDnsProbeSpec]]
        | dict[tuple[str, str, str], list[PlainDnsProbeSpec]]
    ),
    pending_by_name_type: dict[tuple[str, str], deque[PlainDnsProbeSpec]] | None = None,
    *,
    default_rdtype: str | None = None,
) -> tuple[list[tuple[PlainDnsProbeSpec, MassDnsParsedResult]], int, int]:
    matched: list[tuple[PlainDnsProbeSpec, MassDnsParsedResult]] = []
    unmatched = 0
    stdout_lines = 0
    resolved_probe_ids: set[str] = set()
    by_key = {
        key: value if isinstance(value, deque) else deque(value)
        for key, value in pending_by_key.items()
    }
    if pending_by_name_type is None:
        by_name_type: dict[tuple[str, str], deque[PlainDnsProbeSpec]] = defaultdict(deque)
        for queue in by_key.values():
            for spec in queue:
                by_name_type[_name_type_identity_key(spec.qname, spec.rdtype)].append(spec)
    else:
        by_name_type = {
            key: value if isinstance(value, deque) else deque(value)
            for key, value in pending_by_name_type.items()
        }

    def _pop_pending(queue: deque[PlainDnsProbeSpec] | None) -> PlainDnsProbeSpec | None:
        if queue is None:
            return None
        while queue:
            spec = queue.popleft()
            if spec.probe_id not in resolved_probe_ids:
                return spec
        return None

    while True:
        raw = await stdout.readline()
        if not raw:
            break
        stdout_lines += 1
        line = raw.decode("utf-8", errors="replace").strip()
        if not line:
            continue
        parsed = parse_massdns_ndjson_line(line, default_rdtype=default_rdtype)
        if parsed.resolver:
            spec = _pop_pending(
                by_key.get(_result_identity_key(parsed.resolver, parsed.qname, parsed.rdtype))
            )
        else:
            spec = _pop_pending(
                by_name_type.get(_name_type_identity_key(parsed.qname, parsed.rdtype))
            )
        if spec is None:
            unmatched += 1
            continue
        resolved_probe_ids.add(spec.probe_id)
        matched.append((spec, parsed))
    return matched, unmatched, stdout_lines


async def normalize_massdns_result(
    spec: PlainDnsProbeSpec,
    parsed: MassDnsParsedResult,
    *,
    timeout_s: float,
    baseline_resolvers: list[str],
    baseline_cache: dict[tuple[str, str], list[str]],
) -> ProbeResult:
    if parsed.terminal_error:
        return fail_probe(spec.probe_name, f"timeout_or_error:{parsed.terminal_error[:80]}")
    rcode = parsed.rcode or "UNKNOWN"
    if spec.kind == "positive":
        return await evaluate_positive_probe_result(
            spec.entry,
            probe_name=spec.probe_name,
            qname=spec.qname,
            rcode=rcode,
            answers=parsed.answers or [],
            latency_ms=parsed.latency_ms,
            timeout_s=timeout_s,
            baseline_resolvers=baseline_resolvers,
            baseline_cache=baseline_cache,
        )
    return evaluate_nxdomain_probe_result(
        probe_name=spec.probe_name,
        qname=spec.qname,
        rcode=rcode,
        answer_count=len(parsed.answers or []),
        latency_ms=parsed.latency_ms,
    )


async def _drain_stderr(
    stderr: asyncio.StreamReader,
    *,
    log_level: str,
) -> int:
    lines = 0
    while True:
        raw = await stderr.readline()
        if not raw:
            break
        lines += 1
        text = raw.decode("utf-8", errors="replace").rstrip()
        if not text:
            continue
        if log_level.lower() == "debug":
            logger.debug("massdns stderr: %s", text)
        elif log_level.lower() == "info":
            logger.info("massdns stderr: %s", text)
        elif log_level.lower() == "warning":
            logger.warning("massdns stderr: %s", text)
    return lines


async def start_massdns_worker(
    *,
    config: DnsBackendConfig,
    rdtype: str,
    resolvers: list[str],
) -> _MassDnsWorker:
    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as resolver_file:
        resolver_file.write("\n".join(resolvers))
        resolver_file.write("\n")
        resolver_path = Path(resolver_file.name)
    cmd = build_massdns_command(config=config, rdtype=rdtype, resolver_file=resolver_path)
    logger.debug("massdns session command: %s", " ".join(cmd))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    assert proc.stderr is not None
    stderr_task = asyncio.create_task(_drain_stderr(proc.stderr, log_level=config.stderr_log_level))
    return _MassDnsWorker(proc=proc, resolver_path=resolver_path, stderr_task=stderr_task)


async def close_massdns_worker(worker: _MassDnsWorker) -> int:
    try:
        return await worker.stderr_task
    finally:
        with contextlib.suppress(Exception):
            os.unlink(worker.resolver_path)


def _estimate_session_timeout(timeout_s: float, sent: int) -> float:
    return max(1.0, timeout_s * max(20.0, min(600.0, sent / 50.0)))


async def _run_massdns_attempt(
    *,
    source: PlainDnsSpecSource,
    rdtype: str,
    config: DnsBackendConfig,
    timeout_s: float,
    baseline_resolvers: list[str],
    baseline_cache: dict[tuple[str, str], list[str]],
    already_resolved: set[str],
    on_execution: PlainDnsExecutionCallback | None,
) -> tuple[MassDnsSessionMetrics, set[str], list[PlainDnsProbeExecution], int]:
    resolvers_set: set[str] = set()
    remaining_count = 0
    for spec in source():
        if spec.probe_id in already_resolved:
            continue
        remaining_count += 1
        resolvers_set.add(f"{spec.host}:{spec.port}")
    if remaining_count == 0:
        return MassDnsSessionMetrics(), set(), [], 0
    resolvers = sorted(resolvers_set) or ["127.0.0.1:53"]
    worker = await start_massdns_worker(config=config, rdtype=rdtype, resolvers=resolvers)
    proc = worker.proc
    assert proc.stdin is not None
    assert proc.stdout is not None

    pending_by_key: dict[tuple[str, str, str], deque[PlainDnsProbeSpec]] = defaultdict(deque)
    pending_by_name_type: dict[tuple[str, str], deque[PlainDnsProbeSpec]] = defaultdict(deque)
    in_flight_limit = max(1, config.batch_max_queries)
    current_pending = 0
    pending_cond = asyncio.Condition()
    matched_probe_ids: set[str] = set()
    executions: list[PlainDnsProbeExecution] = []
    stdout_lines = 0
    unmatched = 0
    parsed_results = 0
    terminal_failures_matched = 0
    probes_sent = 0

    async def _record_match(spec: PlainDnsProbeSpec, parsed: MassDnsParsedResult) -> None:
        nonlocal current_pending, parsed_results, terminal_failures_matched
        result = await normalize_massdns_result(
            spec,
            parsed,
            timeout_s=timeout_s,
            baseline_resolvers=baseline_resolvers,
            baseline_cache=baseline_cache,
        )
        execution = PlainDnsProbeExecution(spec=spec, result=result)
        matched_probe_ids.add(spec.probe_id)
        parsed_results += 1
        if parsed.terminal_error:
            terminal_failures_matched += 1
        if on_execution is not None:
            await on_execution(execution)
        else:
            executions.append(execution)
        async with pending_cond:
            current_pending -= 1
            pending_cond.notify_all()

    async def _parse_stdout() -> None:
        nonlocal stdout_lines, unmatched
        while True:
            raw = await proc.stdout.readline()
            if not raw:
                break
            stdout_lines += 1
            line = raw.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            parsed = parse_massdns_ndjson_line(line, default_rdtype=rdtype)
            if parsed.resolver:
                key = _result_identity_key(parsed.resolver, parsed.qname, parsed.rdtype)
                queue = pending_by_key.get(key)
            else:
                key = _name_type_identity_key(parsed.qname, parsed.rdtype)
                queue = pending_by_name_type.get(key)
            if not queue:
                unmatched += 1
                logger.debug("ignoring unmatched massdns line: %s", line[:200])
                continue
            while queue:
                spec = queue.popleft()
                if spec.probe_id not in matched_probe_ids:
                    await _record_match(spec, parsed)
                    break
            else:
                unmatched += 1

    parser_task = asyncio.create_task(_parse_stdout())
    try:
        buffer = bytearray()
        for spec in source():
            if spec.probe_id in already_resolved:
                continue
            async with pending_cond:
                while current_pending >= in_flight_limit:
                    await pending_cond.wait()
            pending_by_key[_spec_identity_key(spec)].append(spec)
            pending_by_name_type[_name_type_identity_key(spec.qname, spec.rdtype)].append(spec)
            current_pending += 1
            probes_sent += 1
            buffer.extend(build_manifest_line(spec).encode("utf-8"))
            if len(buffer) >= 65536:
                proc.stdin.write(buffer)
                buffer.clear()
                await proc.stdin.drain()
        if buffer:
            proc.stdin.write(buffer)
            await proc.stdin.drain()
        proc.stdin.close()
        await proc.stdin.wait_closed()

        timeout_window = _estimate_session_timeout(timeout_s, max(probes_sent, remaining_count))
        async with asyncio.timeout(timeout_window):
            await parser_task
            return_code = await proc.wait()
        stderr_lines = await close_massdns_worker(worker)
    except TimeoutError as exc:
        with contextlib.suppress(ProcessLookupError):
            proc.terminate()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(proc.wait(), timeout=1.0)
        parser_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await parser_task
        worker.stderr_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await worker.stderr_task
        with contextlib.suppress(Exception):
            os.unlink(worker.resolver_path)
        raise TimeoutError("massdns batch timed out") from exc
    except Exception:
        with contextlib.suppress(ProcessLookupError):
            proc.terminate()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(proc.wait(), timeout=1.0)
        parser_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await parser_task
        worker.stderr_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await worker.stderr_task
        with contextlib.suppress(Exception):
            os.unlink(worker.resolver_path)
        raise

    metrics = MassDnsSessionMetrics(
        stdout_lines=stdout_lines,
        stderr_lines=stderr_lines,
        parsed_results=parsed_results,
        unmatched_results=unmatched,
        terminal_failures_matched=terminal_failures_matched,
        probes_sent=probes_sent,
        exit_code=return_code,
    )
    return metrics, matched_probe_ids, executions, remaining_count


async def run_massdns_rdtype_session(
    specs: Iterable[PlainDnsProbeSpec] | PlainDnsSpecSource,
    *,
    rdtype: str,
    config: DnsBackendConfig,
    timeout_s: float,
    baseline_resolvers: list[str],
    baseline_cache: dict[tuple[str, str], list[str]],
    on_execution: PlainDnsExecutionCallback | None = None,
) -> tuple[list[PlainDnsProbeExecution], MassDnsSessionMetrics]:
    if callable(specs):
        source = specs
    else:
        materialized = tuple(specs)

        def source() -> Iterable[PlainDnsProbeSpec]:
            return iter(materialized)

    resolved_probe_ids: set[str] = set()
    all_executions: list[PlainDnsProbeExecution] = []
    total = MassDnsSessionMetrics()
    restarts = 0

    def _count_remaining() -> int:
        return sum(1 for spec in source() if spec.probe_id not in resolved_probe_ids)

    while _count_remaining() > 0:
        metrics, matched_ids, executions, remaining_before = await _run_massdns_attempt(
            source=source,
            rdtype=rdtype,
            config=config,
            timeout_s=timeout_s,
            baseline_resolvers=baseline_resolvers,
            baseline_cache=baseline_cache,
            already_resolved=resolved_probe_ids,
            on_execution=on_execution,
        )
        resolved_probe_ids.update(matched_ids)
        if on_execution is None:
            all_executions.extend(executions)
        exit_code = total.exit_code if total.exit_code != 0 else metrics.exit_code
        total = MassDnsSessionMetrics(
            stdout_lines=total.stdout_lines + metrics.stdout_lines,
            stderr_lines=total.stderr_lines + metrics.stderr_lines,
            parsed_results=total.parsed_results + metrics.parsed_results,
            unmatched_results=total.unmatched_results + metrics.unmatched_results,
            terminal_failures_matched=(
                total.terminal_failures_matched + metrics.terminal_failures_matched
            ),
            probes_sent=total.probes_sent + metrics.probes_sent,
            exit_code=exit_code,
            restarts=restarts,
        )
        logger.debug(
            (
                "massdns session rdtype=%s sent=%d parsed=%d stdout_lines=%d "
                "stderr_lines=%d unmatched=%d terminal_failures=%d exit_code=%d restart=%d"
            ),
            rdtype,
            metrics.probes_sent,
            metrics.parsed_results,
            metrics.stdout_lines,
            metrics.stderr_lines,
            metrics.unmatched_results,
            metrics.terminal_failures_matched,
            metrics.exit_code,
            restarts,
        )
        if metrics.exit_code == 0:
            break
        if _count_remaining() == 0 or remaining_before == 0:
            break
        restarts += 1
        logger.warning(
            "massdns session rdtype=%s exited non-zero, restarting unresolved probes",
            rdtype,
        )

    total = MassDnsSessionMetrics(
        stdout_lines=total.stdout_lines,
        stderr_lines=total.stderr_lines,
        parsed_results=total.parsed_results,
        unmatched_results=total.unmatched_results,
        terminal_failures_matched=total.terminal_failures_matched,
        probes_sent=total.probes_sent,
        exit_code=total.exit_code,
        restarts=restarts,
    )

    unresolved_count = _count_remaining()
    if unresolved_count:
        if total.exit_code != 0 and config.fallback_to_python_on_error:
            pending_batch: list[PlainDnsProbeSpec] = []
            for spec in source():
                if spec.probe_id in resolved_probe_ids:
                    continue
                pending_batch.append(spec)
                if len(pending_batch) >= max(1, config.batch_max_queries):
                    fallback_results = await run_python_plain_dns_batch(
                        pending_batch,
                        timeout_s=timeout_s,
                        baseline_resolvers=baseline_resolvers,
                        baseline_cache=baseline_cache,
                        parallelism=1,
                        on_execution=on_execution,
                    )
                    if on_execution is None:
                        all_executions.extend(fallback_results)
                    pending_batch = []
            if pending_batch:
                fallback_results = await run_python_plain_dns_batch(
                    pending_batch,
                    timeout_s=timeout_s,
                    baseline_resolvers=baseline_resolvers,
                    baseline_cache=baseline_cache,
                    parallelism=1,
                    on_execution=on_execution,
                )
                if on_execution is None:
                    all_executions.extend(fallback_results)
        elif total.exit_code != 0 and not config.fallback_to_python_on_error:
            raise RuntimeError(f"massdns session exited with code {total.exit_code}")
        else:
            for spec in source():
                if spec.probe_id in resolved_probe_ids:
                    continue
                execution = PlainDnsProbeExecution(
                    spec=spec,
                    result=fail_probe(spec.probe_name, "timeout_or_error:massdns_unmatched"),
                )
                if on_execution is not None:
                    await on_execution(execution)
                else:
                    all_executions.append(execution)
    return all_executions, total


async def run_massdns_batch(
    specs: list[PlainDnsProbeSpec],
    *,
    config: DnsBackendConfig,
    timeout_s: float,
    baseline_resolvers: list[str],
    baseline_cache: dict[tuple[str, str], list[str]],
    on_execution: PlainDnsExecutionCallback | None = None,
) -> tuple[list[PlainDnsProbeExecution], MassDnsSessionMetrics]:
    if not specs:
        return [], MassDnsSessionMetrics()
    return await run_massdns_rdtype_session(
        specs,
        rdtype=specs[0].rdtype.upper(),
        config=config,
        timeout_s=timeout_s,
        baseline_resolvers=baseline_resolvers,
        baseline_cache=baseline_cache,
        on_execution=on_execution,
    )
