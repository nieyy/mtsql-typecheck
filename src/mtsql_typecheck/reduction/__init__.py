"""Reduction subsystem: replay of mismatch candidates and counterexample
reduction (D2 milestone, phases 3+4)."""

from mtsql_typecheck.reduction.engine import reduce_candidate
from mtsql_typecheck.reduction.replay import replay_candidate

__all__ = ["replay_candidate", "reduce_candidate"]
