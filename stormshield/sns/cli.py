#!/usr/bin/env python3

"""cli to connect to Stormshield Network Security appliances"""

from __future__ import annotations

import argparse
import atexit
import getpass
import logging
import logging.handlers
import os
import platform
import re
import sys
from typing import Any, cast

import defusedxml.minidom

from stormshield.sns.sslclient import ServerError, SSLClient, TOTPNeededError
from stormshield.sns.sslclient.__version__ import __version__ as libversion

try:  # optional, only needed for history and completion
    import readline
except ImportError:  # pragma: no cover - Windows without pyreadline3
    readline = None  # type: ignore[assignment]

CLI_EXTRA_HINT = (
    "snscli needs its optional dependencies: pip install 'stormshield.sns.sslclient[cli]'"
)

OUTPUT_LEVELV_NUM = 60  # log command response
COMMAND_LEVELV_NUM = 59  # log command input

EMPTY_RE = re.compile(r"^\s*$")
#: matches the urllib3 error naming the certificate CN we failed to match
CN_MISMATCH_RE = re.compile(r"doesn't match '(.*)'")

#: environment variable used to pass the password without exposing it in `ps`
PASSWORD_ENV = "SNSCLI_PASSWORD"


def _build_formatter() -> Any:
    """Build the colored log formatter, failing with a clear message."""

    try:
        from colorlog import LevelFormatter
    except ImportError as exc:  # pragma: no cover
        raise SystemExit(CLI_EXTRA_HINT) from exc

    return LevelFormatter(
        fmt={
            "DEBUG": "%(log_color)s%(levelname)-8s%(reset)s %(message)s",
            "INFO": "%(log_color)s%(levelname)-8s%(reset)s %(message)s",
            "WARNING": "%(log_color)s%(levelname)-8s%(reset)s %(message)s",
            "ERROR": "%(log_color)s%(levelname)-8s%(reset)s %(message)s",
            "CRITICAL": "%(log_color)s%(levelname)-8s%(reset)s %(message)s",
            "OUTPUT": "%(message)s",
            "COMMAND": "%(message)s",
        },
        datefmt=None,
        reset=True,
        log_colors={
            "DEBUG": "green",
            "INFO": "cyan",
            "WARNING": "yellow",
            "ERROR": "red",
            "CRITICAL": "red,bg_white",
        },
        secondary_log_colors={},
        style="%",
    )


def _highlight_xml(xml: str) -> str:
    """Pretty print and colorize an XML answer."""

    try:
        from pygments import highlight
        from pygments.formatters import TerminalFormatter
        from pygments.lexers import XmlLexer
    except ImportError as exc:  # pragma: no cover
        raise SystemExit(CLI_EXTRA_HINT) from exc

    return highlight(defusedxml.minidom.parseString(xml).toprettyxml(), XmlLexer(), TerminalFormatter())


class CommandFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelname != "COMMAND"


class SNSLogger(logging.Logger):
    """Logger exposing the CLI's ``OUTPUT`` and ``COMMAND`` levels.

    A subclass rather than methods bolted onto :class:`logging.Logger`, which
    would leak the two levels into every logger of the host application.
    """

    def output(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log a command answer."""

        self._log(OUTPUT_LEVELV_NUM, message, args, **kwargs)

    def command(self, message: str, *args: Any, **kwargs: Any) -> None:
        """Log a command input."""

        self._log(COMMAND_LEVELV_NUM, message, args, **kwargs)


def make_completer():
    """Load completer for readline"""

    with open(SSLClient.get_completer()) as completelist:
        vocabulary = [line.replace(".", " ").strip("\n") for line in completelist]

    def custom_complete(text, state):
        results = [x for x in vocabulary if x.startswith(text)] + [None]
        return results[state]

    return custom_complete


def build_parser() -> argparse.ArgumentParser:
    """Build the command line parser.

    ``add_help=False`` frees ``-h`` for ``--host``; without it argparse would
    need ``conflict_handler="resolve"``, which silently swallows duplicated
    short options instead of reporting them.
    """

    parser = argparse.ArgumentParser(prog="snscli", add_help=False)
    parser.add_argument("--help", action="help", help="Show this help message and exit")

    group = parser.add_argument_group("Connection parameters")
    group.add_argument("-h", "--host", help="Remote UTM", default=None)
    group.add_argument("-i", "--ip", help="Remote UTM ip", default=None)
    group.add_argument("-P", "--port", help="Remote port", default=443, type=int)
    group.add_argument("--proxy", help="Proxy URL (scheme://user:password@host:port)", default=None)
    group.add_argument(
        "--timeout",
        help="Connection timeout in seconds (default: %(default)s, 0 or -1 to wait forever)",
        default=SSLClient.DEFAULT_TIMEOUT,
        type=float,
    )
    group.add_argument(
        "--retries", help="Retries on connection failure (default: %(default)s)", default=2, type=int
    )

    group = parser.add_argument_group("Authentication parameters")
    group.add_argument("-u", "--user", help="User name", default="admin")
    group.add_argument(
        "-p",
        "--password",
        help=f"Password (prefer the {PASSWORD_ENV} environment variable)",
        default=None,
    )
    group.add_argument("-t", "--totp", help="Time-based one time password", default=None)
    group.add_argument("-U", "--usercert", help="User certificate file", default=None)

    group = parser.add_argument_group("SSL parameters")
    group.add_argument("-C", "--cabundle", help="CA bundle file", default=None)
    group.add_argument("--sslverifypeer", help="Strict SSL CA check", default=True, action="store_true")
    group.add_argument(
        "-k",
        "--no-sslverifypeer",
        help="Disable strict SSL CA check",
        action="store_false",
        dest="sslverifypeer",
    )
    group.add_argument(
        "--sslverifyhost", help="Strict SSL host name check", default=True, action="store_true"
    )
    group.add_argument(
        "-K",
        "--no-sslverifyhost",
        help="Disable strict SSL host name check",
        action="store_false",
        dest="sslverifyhost",
    )

    group = parser.add_argument_group("Protocol parameters")
    group.add_argument("-c", "--credentials", help="Privilege list", default=None)
    group.add_argument("-s", "--script", help="Command script", default=None)
    group.add_argument(
        "-o", "--outputformat", help="Output format", default="ini", choices=["ini", "xml"]
    )

    parser.add_argument("--version", help="Library version", default=False, action="store_true")

    group = parser.add_argument_group("Logging parameters")
    exclusive = group.add_mutually_exclusive_group()
    exclusive.add_argument(
        "-v", "--verbose", help="Increase logging output", default=False, action="store_true"
    )
    exclusive.add_argument(
        "-q", "--quiet", help="Decrease logging output", default=False, action="store_true"
    )
    group.add_argument(
        "--loglvl",
        help="Set explicit log level",
        default=None,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
    )
    group.add_argument("--logfile", help="Output log messages to file", default=None)

    return parser


def setup_logging(args: argparse.Namespace) -> SNSLogger:
    """Configure the root logger and the custom OUTPUT/COMMAND levels."""

    level = logging.INFO
    if args.loglvl is not None:
        level = logging.getLevelName(args.loglvl)
    elif args.verbose:
        level = logging.DEBUG
    elif args.quiet:
        level = logging.WARNING

    logging.addLevelName(OUTPUT_LEVELV_NUM, "OUTPUT")
    logging.addLevelName(COMMAND_LEVELV_NUM, "COMMAND")

    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
    root.setLevel(level)

    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(CommandFilter())
    handler.setFormatter(_build_formatter())
    root.addHandler(handler)

    if args.logfile is not None:
        filehandler: logging.Handler
        if platform.system() != "Windows":
            filehandler = logging.handlers.WatchedFileHandler(args.logfile)
        else:
            filehandler = logging.FileHandler(args.logfile)
        root.addHandler(filehandler)

    # the CLI's own logger; its records propagate to the root handlers above
    previous_class = logging.getLoggerClass()
    logging.setLoggerClass(SNSLogger)
    logger = logging.getLogger("snscli")
    logging.setLoggerClass(previous_class)

    return cast(SNSLogger, logger)


def print_response(logger: SNSLogger, response, outputformat: str) -> None:
    if outputformat == "xml":
        logger.output(_highlight_xml(response.xml))
    else:
        logger.output(response.output)


def run_script(logger: SNSLogger, client: SSLClient, path: str, outputformat: str) -> int:
    """Run a command script, returning the process exit code."""

    try:
        with open(path) as script:
            commands = script.read().splitlines()
    except OSError as exception:
        logging.error("Can't open script file - %s", exception)
        return 1

    for cmd in commands:
        logger.output(cmd)
        if cmd.startswith("#") or EMPTY_RE.match(cmd):
            continue
        try:
            response = client.send_command(cmd)
        except Exception as exception:
            logging.error(str(exception))
            return 1
        print_response(logger, response, outputformat)

    return 0


def setup_readline() -> None:
    """Enable history and completion when readline is available."""

    if readline is None:
        return

    histfile = os.path.join(os.path.expanduser("~"), ".sslclient_history")
    try:
        readline.read_history_file(histfile)
        readline.set_history_length(1000)
    except (FileNotFoundError, OSError):
        pass

    def save_history():
        try:
            readline.write_history_file(histfile)
        except OSError:
            logging.warning("Can't write history")

    atexit.register(save_history)

    readline.parse_and_bind("tab: complete")
    readline.set_completer_delims("")
    readline.set_completer(make_completer())


def interactive(logger: SNSLogger, client: SSLClient, outputformat: str) -> int:
    """Run the interactive prompt, returning the process exit code."""

    setup_readline()

    while True:
        try:
            cmd = input("> ")
        except EOFError:
            return 0
        logger.command(cmd)

        # skip comments
        if cmd.startswith("#"):
            continue

        try:
            response = client.send_command(cmd)
        except ServerError as exception:
            # do not log error on QUIT
            if "quit".startswith(cmd.lower()) and str(exception) == "Server disconnected":
                return 0
            logging.error(str(exception))
            return 1
        except Exception as exception:
            logging.error(str(exception))
            return 1

        if response.ret == client.SRV_RET_DOWNLOAD:
            filename = input("File to save: ")
            try:
                client.download(filename)
                logging.info("File downloaded")
            except Exception as exception:
                logging.error(str(exception))
        elif response.ret == client.SRV_RET_UPLOAD:
            filename = input("File to upload: ")
            try:
                client.upload(filename)
                logging.info("File uploaded")
            except Exception as exception:
                logging.error(str(exception))
        else:
            print_response(logger, response, outputformat)


def connect(args: argparse.Namespace, password: str | None) -> SSLClient:
    """Connect to the appliance, prompting for a TOTP if the appliance asks for one."""

    # 0 and the 1.x `-1` sentinel both mean "wait forever"; urllib3 rejects any
    # non-positive timeout, so they must not be forwarded as is
    timeout = args.timeout if args.timeout > 0 else None
    totp = args.totp

    # first try without totp, if needed ask for totp
    for attempt in range(2):
        try:
            client = SSLClient(
                host=args.host,
                ip=args.ip,
                port=args.port,
                user=args.user,
                password=password,
                totp=totp,
                sslverifypeer=args.sslverifypeer,
                sslverifyhost=args.sslverifyhost,
                credentials=args.credentials,
                proxy=args.proxy,
                timeout=timeout,
                retries=args.retries,
                usercert=args.usercert,
                cabundle=args.cabundle,
                autoconnect=False,
            )
        except Exception as exception:
            logging.error(str(exception))
            raise SystemExit(1) from exception

        try:
            client.connect()
        except TOTPNeededError as exception:
            if attempt == 0 and totp is None:
                logging.warning("Second factor authentication is required.")
                totp = getpass.getpass("Totp:")
                continue
            logging.error(str(exception))
            raise SystemExit(1) from exception
        except Exception as exception:
            search = CN_MISMATCH_RE.search(str(exception))
            if search:
                logging.error(
                    (
                        "Appliance name can't be verified, to force connection "
                        'use "--host %s --ip %s" or "--no-sslverifyhost|-K" options'
                    ),
                    search.group(1),
                    args.ip if args.ip is not None else args.host,
                )
            else:
                logging.error(str(exception))
            raise SystemExit(1) from exception
        else:
            return client

    raise SystemExit(1)  # pragma: no cover


def main() -> int:
    args = build_parser().parse_args()
    logger = setup_logging(args)

    if args.version:
        from requests import __version__ as requestsversion
        from urllib3 import __version__ as urllib3version

        logging.info("snscli - stormshield.sns.sslclient version %s", libversion)
        logging.info(" urllib3 %s", urllib3version)
        logging.info(" requests %s", requestsversion)
        return 0

    if args.host is None:
        logging.error("No host provided")
        return 1

    password = args.password or os.environ.get(PASSWORD_ENV)
    if password is None and args.usercert is None:
        password = getpass.getpass()

    client = connect(args, password)

    # disconnect gracefully at exit
    atexit.register(client.disconnect)

    if args.script is not None:
        return run_script(logger, client, args.script, args.outputformat)

    return interactive(logger, client, args.outputformat)


if __name__ == "__main__":
    # execute only if run as a script
    sys.exit(main())
