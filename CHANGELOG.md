# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

## [2.0.0] - 2026-08-03

Modernisation release. See [MIGRATION.md](MIGRATION.md) for the upgrade path.

### Fixed

- **`snscli -t` set a TOTP instead of a timeout.** `-t` was declared twice, for
  `--timeout` and for `--totp`; argparse's `conflict_handler="resolve"` silently
  gave it to `--totp`. `-t` now means `--totp` only, and the parser rejects
  duplicated options instead of swallowing them.
- **`upload()` poisoned the whole session.** It mutated `self.headers` in place,
  so every request issued after an upload carried the multipart `Content-Type`
  of that upload. The headers are copied now.
- **`upload()` leaked a file descriptor** when the POST raised.
- **`download()` left corrupted files on disk.** The payload was written in full,
  *then* its size and CRC were checked. Downloads now land in a `.part` file that
  is only moved into place after verification, so a failed transfer never
  destroys a previously good file.
- **A malformed answer raised `IndexError`** instead of `ServerError`.
  The `if serverd is not None` guard was a no-op: an `Element` is never `None`.
- **The library hijacked the root logger** (`logging.getLogger()`), capturing the
  host application's logging configuration and emitting full API responses into
  it at DEBUG level. It now logs under `stormshield.sns.sslclient`.
- **No timeout by default**, so an appliance that stopped answering hung the
  caller forever. `SSLClient.DEFAULT_TIMEOUT` is 30 s; pass `timeout=None` to
  restore the old behaviour.
- **`crc.compute_crc32()` raised `TypeError`** when handed a `str`, from a
  leftover Python 2 branch calling `bytearray(data)` without an encoding.
- **`ConfigParser` crashed on an empty answer** (`IndexError` on `lines[0]`,
  `AttributeError` when `output` was `None`).
- **`Response.__repr__` crashed** when `output` was `None`, and otherwise dumped
  the entire payload.
- A `raw` payload lost its trailing newline, a side effect of rendering the
  answer to text and parsing it back.
- **Paged answers looked complete.** The appliance reports row counts and
  truncation flags as attributes of the `<serverd>` node (`total`,
  `too_many_data`, `not_enough_space`, `data_changed`); the client dropped them
  entirely. `CONFIG OBJECT LIST type=host start=0` returns at most 100 rows
  while announcing `total=134`, so iterating `response.data` silently processed
  a quarter of the objects with no way to notice. They are exposed as
  `Response.meta` / `.total` / `.count` / `.truncated`, and `send_command()`
  logs a warning when rows were held back.

- **`sslverifyhost=False` silently widened the set of trusted authorities.**
  That option (and `ip=`) mounts an adapter that builds its own SSL context.
  The context came from `ssl.create_default_context()` with no `cafile`, which
  activates the system trust store; urllib3 then loaded `cabundle` on top, so
  the caller got *their* CA **plus every publicly trusted authority* — while
  host name checking was off. Any certificate signed by any public CA, for any
  name, was accepted. The context is now built with `cafile=cabundle`, which
  keeps `create_default_context` from reaching for the system store.
  Present in 1.x as soon as urllib3 2.x was installed.

### Changed

- **Answers are decoded straight from their XML tree.** 1.x parsed the XML,
  re-serialised it to ini text, then parsed that text back with regexes and
  `shlex`. `Response.data` is now built from the tree, and `Response.output` is
  rendered lazily on first access. Measured on real appliance answers:

  | answer | 1.x | 2.0 |
  |---|---|---|
  | `USER LIST` (116 KB) | 34.6 ms | **4.0 ms** (×8.7) |
  | `CONFIG OBJECT LIST` (26 KB) | 6.9 ms | **1.3 ms** (×5.4) |

- **`crc.py` uses `zlib`** instead of a CRC table written in Python. The SNS CRC
  is the non-finalised IEEE CRC-32, i.e. `zlib.crc32(data) ^ 0xFFFFFFFF`.
  **156× faster** (107 ms/MB → 0.69 ms/MB), and 78 lines of table removed.
- `format_output()` builds its result with a list join instead of repeated
  string concatenation, which was quadratic in the answer size.
- `section_line` parsing uses one compiled regex instead of instantiating a
  `shlex` lexer per line with a hand-maintained `wordchars` allow-list.
- Download chunk size raised from 10 KB to 64 KB.
- Connection failures are retried twice with backoff. Only connection
  establishment is retried — a command that reached the appliance is never
  replayed, as API commands are not idempotent.
- `pygments`, `colorlog` and `pyreadline3` moved to the `cli` extra: importing
  the library no longer pulls in terminal colouring dependencies.

### Added

- `SSLClient` is a context manager: `with SSLClient(...) as client:`.
- `disconnect()` is idempotent and survives an already-dead connection.
- `SNSError`, a common base class for every exception the library raises.
- `Response.from_xml()` / `Response.from_tree()`, and `Response.get()` as a
  shortcut for `response.parser.get()`.
- `Response.serverd_code`, the code of the first serverd node (the transfer
  state), distinct from `Response.code` which reports the final status.
- `Response.meta`, `.total`, `.count`, `.offset` and `.truncated` for paged
  answers. `truncated` compares `offset + count` against `total`, not `count`
  alone: past the last page the appliance reports the full `total` alongside
  zero rows, so the naive comparison never terminates.
- `Response.to_dict()` and `Response.json()`. `data` uses `CaseInsensitiveDict`,
  which `json.dumps` refuses; these return plain containers and a JSON string.
  Note that every value is a string — the appliance sends XML attributes, so no
  type information ever reaches the client.
- Type annotations throughout, plus a `py.typed` marker.
- `SNSCLI_PASSWORD` environment variable, so the password no longer has to
  appear in `ps` output via `-p`.
- `--retries` option on `snscli`.
- An offline test suite (155 tests) built on XML answers captured from a real
  appliance, and a locale-independent live suite behind the `live` marker.
- `tox` environments for Python 3.10–3.13, plus a `live` environment and a
  `lint` environment running ruff and mypy.

### Removed

- **Python 2 leftovers**: `from __future__ import unicode_literals`, the
  `unicode` branch in `quote()`, the `raw_input`/`FileNotFoundError` shims, and
  the `sys.version_info[0] < 3` branch in the parser.
- **urllib3 1.x support** (end of life). `urllib3>=2.0` is now required, which
  collapsed six near-identical `if URLLIB3V2` branches in the adapters.
- `HostNameAdapter` and `DNSResolverHTTPSAdapter`, merged into the single
  `SNSHTTPSAdapter`.
- `setup.py`, replaced by `pyproject.toml` (PEP 517/621).
- Python 3.7–3.9 support; the minimum is now 3.10.
- `SSLClient.SRV_RET_MSG` and `SSLClient.AUTH_FAILED`, and
  `ConfigParser.TOKEN_VALUE_RE`: dead since at least 1.0, referenced nowhere.
  The `SRV_RET_*` and `SSL_SERVERD_*` code constants themselves are kept, and
  `SSL_SERVERD_MSG` is still used to build error messages.
- `MANIFEST.in`: setuptools builds an identical sdist without it now that
  packaging is declared in `pyproject.toml`.

## [1.1.2]

- Disable compression to avoid an issue with later versions of urllib3 (#23)
- Update readline lib for Windows

## [1.1.1]

- Ignore bad xml response from serverd (#22)
- Update for SNS v5 (#17)
