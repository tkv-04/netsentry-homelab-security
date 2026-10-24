from typer.testing import CliRunner

from netsentry.cli import app


def test_version():
    result = CliRunner().invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "NetSentry 0.1.0" in result.output


def test_help_is_available():
    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "check-https" in result.output


def test_gui_escapes_host_in_form():
    from netsentry.gui import _page

    page = _page('<script>alert(1)</script>')
    assert '<script>alert(1)</script>' not in page
    assert '&lt;script&gt;' in page
