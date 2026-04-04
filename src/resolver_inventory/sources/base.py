"""Abstract base class for all source adapters."""

from __future__ import annotations

from abc import ABC, abstractmethod

from resolver_inventory.models import Candidate
from resolver_inventory.settings import SourceEntry


class BaseSource(ABC):
    """A source adapter produces Candidate objects from some upstream input."""

    def __init__(self, entry: SourceEntry) -> None:
        self.entry = entry

    @abstractmethod
    def candidates(self) -> list[Candidate]:
        """Return a list of discovered candidates."""
        ...
