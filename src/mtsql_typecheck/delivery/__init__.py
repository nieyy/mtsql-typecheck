"""D4 delivery layer (design 6.4.6, Phase 4): standalone SQL and regression export.

Submodules here package already-collected evidence into material a human can
execute outside the tool.  Nothing in this package connects to a database, runs
SQL, or performs cleanup; the exported SQL never contains ``DROP``, never uses
``IF NOT EXISTS`` and never enables ``mysql --force`` (design Phase 4 agent
constraints and 6.4.6).
"""
