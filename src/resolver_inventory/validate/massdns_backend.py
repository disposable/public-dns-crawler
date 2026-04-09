"""MassDNS backend for batched plain-DNS probing via streaming pipes."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import tempfile
from collections import defaultdict
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
    resolver: str
    qname: str
    rdtype: str
    rcode: str | None = None
    answers: list[str] | None = None
    latency_ms: float | None = None
    terminal_error: str | None = None


@dataclass(frozen=True, slots=True)
class MassDnsBatchMetrics:
    stdout_lines: int = 0
    stderr_lines: int = 0
    parsed_results: int = 0
    unmatched_results: int = 0
    exit_code: int = 0


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
        str(config.interval_ms),
        "-r",
        str(resolver_file),
    ]
    if config.flush:
        cmd.append("--flush")
    if config.predictable:
        cmd.append("--predictable")
    return cmd


def build_manifest_line(spec: PlainDnsProbeSpec) -> str:
    resolver = f"{spec.host}:{spec.port}"
    return f"{spec.qname} {spec.rdtype} {resolver}\n"


async def stream_manifest_to_massdns(
    stdin: asyncio.StreamWriter,
    specs: list[PlainDnsProbeSpec],
) -> None:
    for spec in specs:
        stdin.write(build_manifest_line(spec).encode("utf-8"))
        await stdin.drain()
    stdin.close()
    await stdin.wait_closed()


def _result_identity_key(resolver: str, qname: str, rdtype: str) -> tuple[str, str, str]:
    q = qname.lower().rstrip(".") + "."
    rdt = rdtype.upper()
    if ":" in resolver and resolver.count(":") == 1:
        host, port = resolver.split(":", 1)
        return host, str(int(port)), q + rdt
    return resolver, "53", q + rdt


def _spec_identity_key(spec: PlainDnsProbeSpec) -> tuple[str, str, str]:
    q = spec.qname.lower().rstrip(".") + "."
    return spec.host, str(spec.port), q + spec.rdtype.upper()


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


def parse_massdns_ndjson_line(line: str) -> MassDnsParsedResult:
    decoded = json.loads(line)
    if not isinstance(decoded, dict):
        raise ValueError("massdns output line is not a JSON object")

    qname = str(decoded.get("name") or decoded.get("qname") or "")
    resolver = str(decoded.get("resolver") or decoded.get("resolver_ip") or "")
    rdtype = str(decoded.get("type") or decoded.get("qtype") or "")
    if not qname or not resolver or not rdtype:
        raise ValueError("massdns output line missing resolver/qname/type")

    rcode = decoded.get("rcode") or decoded.get("status")
    if rcode is None and isinstance(decoded.get("data"), dict):
        rcode = decoded["data"].get("rcode")  # type: ignore[index]

    terminal_error = decoded.get("error") or decoded.get("failure")
    latency_raw = decoded.get("latency_ms") or decoded.get("rt")
    latency_ms: float | None = None
    if isinstance(latency_raw, (int, float)):
        latency_ms = float(latency_raw)

    answers = _extract_answers(decoded, rdtype)
    return MassDnsParsedResult(
        resolver=resolver,
        qname=qname,
        rdtype=rdtype,
        rcode=None if rcode is None else str(rcode).upper(),
        answers=answers,
        latency_ms=latency_ms,
        terminal_error=None if terminal_error is None else str(terminal_error),
    )


async def parse_massdns_ndjson_stream(
    stdout: asyncio.StreamReader,
    pending_by_key: dict[tuple[str, str, str], list[PlainDnsProbeSpec]],
    *,
    idle_timeout_s: float | None = None,
) -> tuple[list[tuple[PlainDnsProbeSpec, MassDnsParsedResult]], int, int]:
    matched: list[tuple[PlainDnsProbeSpec, MassDnsParsedResult]] = []
    unmatched = 0
    stdout_lines = 0
    while True:
        try:
            if idle_timeout_s is None:
                raw = await stdout.readline()
            else:
                raw = await asyncio.wait_for(stdout.readline(), timeout=idle_timeout_s)
        except TimeoutError as exc:
            raise TimeoutError("massdns stdout read timed out") from exc
        if not raw:
            break
        stdout_lines += 1
        line = raw.decode("utf-8", errors="replace").strip()
        if not line:
            continue
        parsed = parse_massdns_ndjson_line(line)
        key = _result_identity_key(parsed.resolver, parsed.qname, parsed.rdtype)
        pending = pending_by_key.get(key)
        if not pending:
            unmatched += 1
            continue
        spec = pending.pop(0)
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


async def run_massdns_batch(
    specs: list[PlainDnsProbeSpec],
    *,
    config: DnsBackendConfig,
    timeout_s: float,
    baseline_resolvers: list[str],
    baseline_cache: dict[tuple[str, str], list[str]],
    on_execution: PlainDnsExecutionCallback | None = None,
) -> tuple[list[PlainDnsProbeExecution], MassDnsBatchMetrics]:
    if not specs:
        return [], MassDnsBatchMetrics()

    pending_by_key: dict[tuple[str, str, str], list[PlainDnsProbeSpec]] = defaultdict(list)
    for spec in specs:
        pending_by_key[_spec_identity_key(spec)].append(spec)

    resolvers = sorted({f"{spec.host}:{spec.port}" for spec in specs}) or ["127.0.0.1:53"]
    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as resolver_file:
        resolver_file.write("\n".join(resolvers))
        resolver_file.write("\n")
        resolver_path = Path(resolver_file.name)

    rdtype = specs[0].rdtype.upper()
    cmd = build_massdns_command(config=config, rdtype=rdtype, resolver_file=resolver_path)
    logger.debug("massdns command: %s", " ".join(cmd))

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        raise
    except Exception as exc:
        raise RuntimeError(f"failed to start massdns: {exc}") from exc

    assert proc.stdin is not None
    assert proc.stdout is not None
    assert proc.stderr is not None

    stderr_task = asyncio.create_task(_drain_stderr(proc.stderr, log_level=config.stderr_log_level))
    try:
        manifest_task = asyncio.create_task(stream_manifest_to_massdns(proc.stdin, specs))
        # Bound stalls on stdout so validation.timeout_ms still applies when
        # the subprocess wedges or stops producing output.
        matched, unmatched, stdout_lines = await parse_massdns_ndjson_stream(
            proc.stdout,
            pending_by_key,
            idle_timeout_s=max(1.0, timeout_s),
        )
        await manifest_task
        return_code = await asyncio.wait_for(proc.wait(), timeout=max(1.0, timeout_s * 2))
        stderr_lines = await stderr_task
    except Exception:
        with contextlib.suppress(ProcessLookupError):
            proc.terminate()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(proc.wait(), timeout=1.0)
        stderr_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await stderr_task
        raise
    finally:
        with contextlib.suppress(Exception):
            os.unlink(resolver_path)

    executions: list[PlainDnsProbeExecution] = []
    yielded_count = 0
    for spec, parsed in matched:
        result = await normalize_massdns_result(
            spec,
            parsed,
            timeout_s=timeout_s,
            baseline_resolvers=baseline_resolvers,
            baseline_cache=baseline_cache,
        )
        execution = PlainDnsProbeExecution(spec=spec, result=result)
        yielded_count += 1
        if on_execution is not None:
            await on_execution(execution)
        else:
            executions.append(execution)

    unresolved = [spec for pending in pending_by_key.values() for spec in pending]
    if return_code != 0 and not yielded_count:
        raise RuntimeError(f"massdns exited with code {return_code}")

    if unresolved:
        if return_code != 0 and config.fallback_to_python_on_error:
            fallback_results = await run_python_plain_dns_batch(
                unresolved,
                timeout_s=timeout_s,
                baseline_resolvers=baseline_resolvers,
                baseline_cache=baseline_cache,
                parallelism=1,
                on_execution=on_execution,
            )
            if on_execution is None:
                executions.extend(fallback_results)
        else:
            for spec in unresolved:
                execution = PlainDnsProbeExecution(
                    spec=spec,
                    result=fail_probe(spec.probe_name, "timeout_or_error:massdns_unmatched"),
                )
                if on_execution is not None:
                    await on_execution(execution)
                else:
                    executions.append(execution)

    metrics = MassDnsBatchMetrics(
        stdout_lines=stdout_lines,
        parsed_results=yielded_count,
        unmatched_results=unmatched,
        stderr_lines=stderr_lines,
        exit_code=return_code,
    )
    return executions, metrics
