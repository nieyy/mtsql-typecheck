"""Reporting subpackage (design 6.4.4): pure count/coverage/finding models.

Every function in this package is pure: no file I/O, no database access, no
clock.  The caller supplies typed inputs read elsewhere (D4 evidence
assessment, native manifests, the rule registry).  Counters are ``int | None``
when the source cannot provide the number; they are never fabricated.
Percentages are deliberately unrepresentable (design 6.4.4: denominators that
are unknown must be displayed as unknown, not divided by), and no aggregate
ever produces a ``confirmed_bug`` boolean -- confirmation only comes from a
bound :class:`~mtsql_typecheck.contracts.delivery.FindingReview`.
"""
