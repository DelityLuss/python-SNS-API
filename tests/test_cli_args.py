"""Command line parsing - no live appliance needed."""

import pytest

from stormshield.sns.cli import build_parser


@pytest.fixture
def parser():
    return build_parser()


def test_timeout_and_totp_do_not_collide(parser):
    """1.x declared -t twice; argparse's `resolve` handler silently gave it
    to --totp, so `snscli -t 30` set a TOTP instead of a timeout."""

    args = parser.parse_args(["-h", "fw", "-t", "123456"])
    assert args.totp == "123456"
    assert args.timeout == 30  # untouched default

    args = parser.parse_args(["-h", "fw", "--timeout", "5"])
    assert args.timeout == 5
    assert args.totp is None


def test_no_duplicate_short_options():
    """Guard the whole parser against a new silent collision."""

    parser = build_parser()
    seen = {}
    for action in parser._actions:
        for opt in action.option_strings:
            assert opt not in seen, f"{opt} declared twice: {seen.get(opt)} and {action.dest}"
            seen[opt] = action.dest


def test_host_short_option_is_h(parser):
    args = parser.parse_args(["-h", "10.0.0.254"])
    assert args.host == "10.0.0.254"


def test_long_help_is_available(parser, capsys):
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["--help"])
    assert exc.value.code == 0
    assert "--host" in capsys.readouterr().out


def test_sslverify_defaults_and_negation(parser):
    args = parser.parse_args(["-h", "fw"])
    assert args.sslverifypeer is True
    assert args.sslverifyhost is True

    args = parser.parse_args(["-h", "fw", "-k", "-K"])
    assert args.sslverifypeer is False
    assert args.sslverifyhost is False

    args = parser.parse_args(["-h", "fw", "--no-sslverifypeer"])
    assert args.sslverifypeer is False


def test_outputformat_is_validated(parser):
    assert parser.parse_args(["-h", "fw", "-o", "xml"]).outputformat == "xml"
    with pytest.raises(SystemExit):
        parser.parse_args(["-h", "fw", "-o", "yaml"])


def test_timeout_zero_means_no_timeout(parser):
    assert parser.parse_args(["-h", "fw", "--timeout", "0"]).timeout == 0


def test_verbose_and_quiet_are_exclusive(parser):
    with pytest.raises(SystemExit):
        parser.parse_args(["-h", "fw", "-v", "-q"])


def test_password_env_var_is_used(monkeypatch):
    from stormshield.sns.cli import PASSWORD_ENV

    monkeypatch.setenv(PASSWORD_ENV, "from-env")
    args = build_parser().parse_args(["-h", "fw"])
    assert args.password is None
    assert (args.password or __import__("os").environ.get(PASSWORD_ENV)) == "from-env"
