# python-SNS-API

A Python client for the Stormshield Network Security appliance SSL API.

Requires **Python 3.10 or later** and **urllib3 2.x**.
Upgrading from 1.x? See [MIGRATION.md](MIGRATION.md).

## Install

From PyPI:

```console
$ pip install stormshield.sns.sslclient          # library only
$ pip install 'stormshield.sns.sslclient[cli]'   # + the snscli command
```

From source:

```console
$ pip install '.[cli]'
```

## API usage

```python
from stormshield.sns.sslclient import SSLClient

with SSLClient(
    host="10.0.0.254", port=443,
    user='admin', password='password',
    sslverifyhost=False,
) as client:

    response = client.send_command("SYSTEM PROPERTY")

    if response:
        print(f"Model: {response.data['Result']['Model']}")
        print(f"Firmware version: {response.data['Result']['Version']}")
    else:
        print(f"Command failed: {response.output}")
```

The client is a context manager, so it disconnects even if a command raises.
`client.disconnect()` still works if you prefer to manage the session yourself,
and calling it twice is harmless.

* **Note:** Starting from the 5.0 firmware, a custom CA is used by default by the SSL API. To continue to connect checking the certificate authority of the appliance, the "SNS-WebServer-default-authority" CA must be retrieved from each appliance, then added to a cabundle.pem file. Alternatively, CA verification can be bypassed using `sslverifypeer=False`.

### Which CA bundle is used

`cabundle` is the **only** set of authorities trusted — it replaces the system
trust store, it does not add to it. The bundle shipped with the library
(`stormshield/sns/bundle.ca`) holds the two Stormshield roots that sign factory
appliance certificates, and nothing else.

So an appliance fronted by a commercial certificate (Let's Encrypt, DigiCert…)
is *not* verifiable with the default bundle. Point `cabundle` at the matching
roots instead:

```python
import certifi
SSLClient(host="firewall.example.com", cabundle=certifi.where(), ...)
```

### Command results

Command results are available in text, xml or python structure formats:

```python
>>> response = client.send_command("CONFIG NTP SERVER LIST")

>>> print(response.output)
101 code=00a01000 msg="Begin" format="section_line"
[Result]
name=ntp1.stormshieldcs.eu keynum=none type=host
name=ntp2.stormshieldcs.eu keynum=none type=host
100 code=00a00100 msg="Ok"

>>> print(response.xml)
<?xml version="1.0"?>
<nws code="100" msg="OK"><serverd ret="101" code="00a01000" msg="Begin"><data format="section_line"><section title="Result"><line><key name="name" value="ntp1.stormshieldcs.eu"/><key name="keynum" value="none"/><key name="type" value="host"/></line><line><key name="name" value="ntp2.stormshieldcs.eu"/><key name="keynum" value="none"/><key name="type" value="host"/></line></section></data></serverd><serverd ret="100" code="00a00100" msg="Ok"></serverd></nws>

>>> print(response.data)
{'Result': [{'name': 'ntp1.stormshieldcs.eu', 'keynum': 'none', 'type': 'host'}, {'name': 'ntp2.stormshieldcs.eu', 'keynum': 'none', 'type': 'host'}]}
```

`data` is decoded directly from the XML answer; `output` is only rendered if you
read it, so code that works on `data` never pays for the text formatting.

The keys of the `data` property are case insensitive, `response.data['Result'][0]['name']` and `response.data['ReSuLt'][0]['NaMe']` will return the same value.

Result tokens are also available via `response.get()` (or `response.parser.get()`),
which accepts a default to return when the token is absent:

```python
>>> print(response.data['Server']['3'])
Traceback (most recent call last):
  ...
KeyError: '3'

>>> print(response.get(section='Server', token='3', default=None))
None
```

### JSON

`data` uses `CaseInsensitiveDict`, which `json.dumps` cannot serialise. Use
`to_dict()` for plain containers, or `json()` for a string:

```python
>>> json.dumps(response.data)
TypeError: Object of type CaseInsensitiveDict is not JSON serializable

>>> response.to_dict()
{'Result': [{'name': 'ntp1.stormshieldcs.eu', 'keynum': 'none', 'type': 'host'}]}

>>> print(response.json(indent=2))
{
  "Result": [
    {"name": "ntp1.stormshieldcs.eu", "keynum": "none", "type": "host"}
  ]
}
```

**Every value is a string.** The appliance answers in XML, where everything is
a text attribute, so no type information ever reaches the client: `"modify": "1"`
is the text `1`, not the integer, and `"global": "0"` is not a boolean. The
library does not guess — converting is the caller's decision.

The appliance itself has no JSON mode. `output=json` is rejected by some
commands and silently ignored by others, which answer in their usual format;
only `output=xml` is real.

### Paged answers

Commands that page their results announce how many rows exist in total. Those
counters are answer metadata, not rows, so they live outside `data`:

```python
>>> response = client.send_command("CONFIG OBJECT LIST type=host start=0")
>>> response.count, response.total, response.truncated
(100, 134, True)
>>> response.meta
{'total': '134', 'data_changed': '0', 'too_many_data': '0', 'not_enough_space': '0'}
```

Iterating `response.data['Object']` alone would process 100 of 134 objects
without any error. Page until `truncated` is False:

```python
objects, start = [], 0
while True:
    response = client.send_command(f"CONFIG OBJECT LIST type=host start={start}")
    objects.extend(response.data['Object'])
    if not response.truncated:
        break
    start += response.count
```

`send_command()` also logs a warning whenever rows were held back. `truncated`
compares `offset + count` against `total` — `offset` is read from the command's
`start=` argument — because past the last page the appliance still reports the
full `total` next to zero rows, and comparing `count` alone would never
terminate.

### Error handling

Every exception derives from `SNSError`:

```python
from stormshield.sns.sslclient import (
    SNSError,             # base class
    MissingHost, MissingAuth, MissingCABundle,
    AuthenticationError, TOTPNeededError,
    ServerError, FileError,
)
```

A command that the appliance rejects is *not* an exception: check the response.
`bool(response)` is true when `ret` is OK or a warning (100–199).

### File upload/download

Files can be downloaded to or uploaded from the client host by adding a redirection to a file with '>' or '<' at the end of the configuration command.

```python
>>> client.send_command("CONFIG BACKUP list=all > /tmp/mybackup.na")
100 code=00a00100 msg="Ok"
```

Downloads are written to a temporary file and only moved into place once their
size and CRC match what the appliance announced, so a failed transfer never
leaves a truncated file behind.

### Logging

The library logs under the `stormshield.sns.sslclient` namespace and does not
touch the root logger:

```python
logging.getLogger("stormshield.sns.sslclient").setLevel(logging.DEBUG)
```

Note that DEBUG logs the full body of every API answer.

## snscli

`snscli` is a python cli for executing configuration commands and scripts on Stormshield Network Security appliances.

* Output format can be chosen between section/ini or xml
* File upload and download available with adding `< upload` or `> download` at the end of the command
* Client can execute script files using `--script` option.
* Comments are allowed with `#`

```console
$ snscli --host <utm>
$ snscli --host <utm> --user admin --script config.script
```

Pass the password through the environment rather than `--password`, which is
visible in `ps`:

```console
$ SNSCLI_PASSWORD=secret snscli --host <utm> --script config.script
```

Concerning the SSL validation:

* For the first connection to a new appliance, ssl host name verification can be bypassed with `--no-sslverifyhost` option.
* To connect to a known appliance with the default certificate use `--host <serial> --ip <ip address>` to validate the peer certificate.
* If a custom CA and certificate is installed, use `--host myfirewall.tld --cabundle <ca.pem>`. CA bundle should contain at least the root CA.
* For client certificate authentication, the expected format is a PEM file with the certificate and the unencrypted key concatenated.

* **Note:** Starting from the 5.0 firmware, a custom CA is used by default by the SSL API. To continue to connect checking the certificate authority of the appliance, the "SNS-WebServer-default-authority" CA must be retrieved from each appliance, then added to a cabundle.pem file. Alternatively, CA verification can be bypassed using `--no-sslverifypeer` option.

## Proxy

The library and `snscli` tool support HTTP and SOCKS proxies, use `--proxy scheme://user:password@host:port` option.

## Build

```console
$ python3 -m build
```

## Tests

The default suite is offline: it replays XML answers captured from a real
appliance, stored under `tests/fixtures`.

```console
$ pytest
```

Tests marked `live` need a reachable appliance and skip otherwise:

```console
$ APPLIANCE=10.0.0.254 PASSWORD=password pytest -m live
```

Optional variables unlock the remaining connection modes: `SERIAL` (host name
check against the certificate CN), `FQDN` + `CABUNDLE` (custom CA), `CERT`
(client certificate authentication), `PROXY`.

Across supported interpreters:

```console
$ tox
```

To run `snscli` from the source folder without install:

```console
$ PYTHONPATH=. python3 -m stormshield.sns.cli --help
```

## Links

* [Stormshield corporate website](https://www.stormshield.com)
* [CLI commands reference guide](https://documentation.stormshield.eu/SNS/v5/en/Content/CLI_Serverd_Commands_reference_Guide_v5/Introduction.htm)
* [Python SNS API example scripts](https://github.com/stormshield/sns-scripting/tree/master/python)
