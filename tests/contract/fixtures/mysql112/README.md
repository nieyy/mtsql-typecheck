# mysql112 synthetic protocol fixtures (D3 Phase 2)

**These fixtures are SYNTHETIC.**  Every `.bin` file in this directory was
hand-built byte-by-byte from the MySQL client/server text-protocol layout and
PyMySQL 1.1.2's packet structures; **none of them was captured from a real
MySQL/MTSQL server**.  They exist so the offline unit tests can pin the shim's
parsing behaviour without a database connection.  They do NOT certify the
driver against a real server (that is the D3 Phase 2/4 online gate and is
NOT_RUN until a dedicated instance is available).

## Layout

Each pair is a raw packet byte stream plus the expected parsed structure:

- `*.bin` — one complete MySQL message as it appears on the wire: for each
  frame, a 3-byte little-endian payload length + 1-byte sequence number +
  payload.  Single-frame files use one frame; `message_two_fragments.bin`
  exercises multi-frame continuation.
- On the real wire a message continues only after a 16 MiB - 1 frame, so a
  small synthetic 2-fragment stream is not a legal real-server message.  The
  reader makes the continuation threshold injectable for tests
  (`continuation_threshold`, real connections keep 16 MiB - 1);
  `message_two_fragments.json` declares its threshold so the test seam matches
  the documented stream layout.
- `*.json` — `frames` (per-frame payload length and sequence),
  `payload_hex` (the reassembled payload), and `expected` (what the shim's
  parsers must return).

## Files

| Fixture | Content |
|---|---|
| `ok_warning_count` | OK packet, `warning_count=5`, status `AUTOCOMMIT` |
| `err_sqlstate` | ERR packet, `errno=1049`, SQLSTATE `42S02` |
| `eof_deprecated_terminator` | `CLIENT_DEPRECATE_EOF` result terminator (OK packet), `warning_count=7`, `SERVER_MORE_RESULTS_EXISTS` set |
| `eof_column_definition` | classic column-definition EOF, `warning_count=3` (P02: must never be taken as the final count) |
| `eof_result_final` | classic final result EOF, `warning_count=7` (authoritative) |
| `field_newdecimal` | field packet for NEWDECIMAL (246), `decimals=2`, charset 63 (binary) |
| `message_two_fragments` | 2-fragment reassembled message under the 16 MiB cap |

## Certification status

SYNTHETIC only.  Real-server packet captures, if ever added here, must be
labelled with the server build, capture date and authorization, and must
never contain credentials or unreviewed data.
