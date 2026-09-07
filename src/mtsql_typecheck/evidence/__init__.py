"""D4 evidence layer: safe reading, snapshotting and delivery manifests.

Phase 1 modules (design 6.4.1/6.4.2/6.5):

- ``reader``   : bounded, symlink-refusing source reader (agent B)
- ``native``   : native kind detection and file-closure enumeration (this
  package, agent C)
- ``snapshot`` : immutable raw snapshots (agent B)
- ``manifest`` : delivery manifest writer/validator (agent C)

Importing this package performs no I/O.
"""
