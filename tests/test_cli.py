from click.testing import CliRunner

from cable.cli import main


def test_qr_command_runs_without_network():
    runner = CliRunner()
    result = runner.invoke(main, ["qr"])

    assert result.exit_code == 0
    assert "URI: FIDO:/" in result.output
    # The terminal-rendered QR code is drawn with ANSI SGR escape sequences.
    assert "\x1b[" in result.output


def test_qr_command_accepts_request_type():
    runner = CliRunner()
    result = runner.invoke(main, ["qr", "--request-type", "mc"])
    assert result.exit_code == 0
    assert "URI: FIDO:/" in result.output


def test_get_assertion_requires_rp_id_and_challenge():
    runner = CliRunner()
    result = runner.invoke(main, ["get-assertion"])
    assert result.exit_code != 0
    assert "rp-id" in result.output or "Missing option" in result.output


def test_make_credential_requires_options():
    runner = CliRunner()
    result = runner.invoke(main, ["make-credential"])
    assert result.exit_code != 0


def test_help_lists_subcommands():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    for name in ("qr", "get-info", "get-assertion", "make-credential"):
        assert name in result.output
