# Migrating from 1.x to 2.0

Most code needs **no change**: `SSLClient(...)`, `send_command()`, `response.data`,
`response.output`, `response.xml`, `response.ret` and `response.parser.get()` all
behave as before.

The points below are the ones that can actually break a caller.

## Requirements

| | 1.x | 2.0 |
|---|---|---|
| Python | 3.7+ | **3.10+** |
| urllib3 | 1.x or 2.x | **2.0+** |

Install the CLI dependencies explicitly if you use `snscli`:

```console
$ pip install 'stormshield.sns.sslclient[cli]'
```

## Behaviour changes

### A default timeout is applied

1.x waited forever. 2.0 defaults to 30 seconds:

```python
client = SSLClient(host="fw", password="pass", timeout=None)  # restore 1.x behaviour
```

### `repr(response)` no longer returns the payload

`__repr__` returned `self.output`, and raised `TypeError` when it was `None`.
It is now a short summary. Use `str(response)` or `response.output` for the text:

```python
print(response)          # unchanged: __str__ still returns output
print(repr(response))    # <Response ret=100 code=00a00100 msg='Ok'>
```

### `sslverifyhost=False` no longer trusts the system authorities

This is the one change that breaks *working* connections. An appliance reached
with `sslverifyhost=False` **and** peer verification left on connected in 1.x
whenever its certificate was signed by a publicly trusted CA — a common setup
when the appliance is fronted by a corporate or commercial certificate. That
worked by accident: the adapter's SSL context pulled in the system trust store
on top of `cabundle` (see the CHANGELOG). 2.0 trusts `cabundle` and nothing else,
so the same call now raises `SSLError`.

Name the authorities you actually trust:

```python
import certifi

# appliance certificate signed by a public CA
client = SSLClient(host="fw", password="pass", sslverifyhost=False,
                   cabundle=certifi.where())

# appliance certificate signed by your own CA
client = SSLClient(host="fw", password="pass", sslverifyhost=False,
                   cabundle="/etc/ssl/private/company-ca.pem")
```

`snscli` takes the same file with `-C/--cabundle`. Callers already passing
`sslverifypeer=False` (`snscli -k`) are unaffected, and so is the default
factory-certificate setup, which the shipped bundle covers.

### `raw` answers keep their trailing newline

1.x dropped the final `\n` of a `format="raw"` payload. If you compared
`response.data` against a literal, add the newline back or use `.rstrip()`.

### Logging moved out of the root logger

1.x called `logging.getLogger()`. If you relied on that to see the library's
DEBUG output, target its namespace explicitly:

```python
logging.getLogger("stormshield.sns.sslclient").setLevel(logging.DEBUG)
```

### `snscli -t`

`-t` was ambiguous and resolved to `--totp`. It now means `--totp` only, and
`--timeout` has no short form. Scripts passing `-t` for a timeout were already
setting a TOTP, so they were already broken — they now need `--timeout`.

## Removed API

| Removed | Replacement |
|---|---|
| `HostNameAdapter` | `SNSHTTPSAdapter(assert_hostname=False, cafile=bundle)` |
| `DNSResolverHTTPSAdapter(cn, host)` | `SNSHTTPSAdapter(cn, cafile=bundle)` |
| `URLLIB3V2` | urllib3 2.x is always assumed |
| `setup.py install` | `pip install .` |

These were internal plumbing; the public entry point has always been `SSLClient`.

Always pass `cafile` — the certificate authority bundle you mounted the session
with, or `None` only when peer verification is disabled. The adapter builds its
own SSL context, and leaving `cafile` out makes it fall back to the system trust
store: your bundle would no longer be the only authority trusted, which is the
widening 2.0 fixed.

## New things worth adopting

```python
from stormshield.sns.sslclient import SSLClient, SNSError

# context manager: disconnects even when a command raises
with SSLClient(host="10.0.0.254", user="admin", password="pass",
               sslverifyhost=False) as client:
    response = client.send_command("SYSTEM PROPERTY")
    print(response.get("Result", "Version"))       # shortcut for parser.get()

# one except clause for the whole library
try:
    ...
except SNSError as exc:
    ...
```
