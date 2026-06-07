"""Tests for the `veriscrape` CLI (no network; the --file path classifies a saved response)."""

from veriscrape import FetchRecord, Verdict
from veriscrape.cli import format_record, main

_SHELL = (
    "<html><head><title>App</title>"
    + "<script>/* pad */</script>" * 120
    + '</head><body><div id="app-mount"></div>'
    + "<noscript>You need to enable JavaScript to run this app.</noscript></body></html>"
)


def test_format_record_shows_verdict_cause_and_status():
    record = FetchRecord(
        url="https://x.test", status=200, verdict=Verdict.EMPTY_SHELL,
        cause="js_app_shell", confidence=0.95,
    )
    out = format_record(record)
    assert "EMPTY_SHELL" in out
    assert "js_app_shell" in out
    assert "200" in out


def test_check_file_flags_negative_verdict_with_nonzero_exit(tmp_path, capsys):
    page = tmp_path / "page.html"
    page.write_text(_SHELL)
    code = main(["check", "--file", str(page)])
    out = capsys.readouterr().out
    assert "EMPTY_SHELL" in out
    assert code == 1  # a detected problem gates a pipeline


def test_check_file_real_content_exits_zero(tmp_path, capsys):
    page = tmp_path / "ok.html"
    page.write_text("<html><body><h1>Real article</h1><p>" + "words " * 200 + "</p></body></html>")
    code = main(["check", "--file", str(page)])
    out = capsys.readouterr().out
    assert "UNVERIFIED" in out
    assert code == 0  # abstain is not a failure
