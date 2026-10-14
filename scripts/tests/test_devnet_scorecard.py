"""Tests for scripts/devnet_scorecard.py.

Pytest prepends this directory, not scripts/, so the script is loaded by path.
"""

from __future__ import annotations

import ast
import json
import os
import sys
from pathlib import Path

import pytest

from conftest import load_script

_FIXTURES = Path(__file__).resolve().parent / "fixtures"
SCRIPT = Path(__file__).resolve().parents[1] / "devnet_scorecard.py"


@pytest.fixture(scope="session")
def sc():
    return load_script("devnet_scorecard")


def _argv(metrics: str | Path, csv_path: str | Path, *extra: str) -> list[str]:
    return ["--metrics", str(metrics), "--csv", str(csv_path), *extra]


def _run(sc, metrics: str | Path, csv_path: str | Path, *extra: str) -> int:
    return sc.main(_argv(metrics, csv_path, *extra))


def _drop_family(text: str, name: str) -> str:
    kept: list[str] = []
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith(f"# TYPE {name} "):
            continue
        if (
            stripped == name
            or stripped.startswith(f"{name} ")
            or stripped.startswith(f"{name}{{")
        ):
            continue
        kept.append(line)
    return "".join(kept)


def test_exit_codes_follow_validator_perf(sc):
    assert (
        sc.EXIT_OK,
        sc.EXIT_ERROR,
        sc.EXIT_USAGE,
        sc.EXIT_THRESHOLD,
    ) == (0, 1, 2, 4)


def test_pep723_block_is_exact():
    source = SCRIPT.read_text(encoding="utf-8")
    assert source.startswith("#!/usr/bin/env -S uv run --script\n")
    assert "# /// script\n" in source
    assert 'requires-python = ">=3.11"\n' in source
    assert "dependencies = []\n" in source
    assert "# ///\n" in source


def test_imports_are_stdlib_only():
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module.split(".", 1)[0])
    extra = sorted({name for name in imported if name not in sys.stdlib_module_names})
    assert extra == []


def test_script_does_not_run_main_on_import(capsys):
    source = SCRIPT.read_text(encoding="utf-8")
    guard_at = source.index('if __name__ == "__main__":')
    assert "sys.exit(main())" in source[guard_at:]
    load_script("devnet_scorecard_guard")
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_csv_flag_takes_a_path(sc):
    action = next(
        a for a in sc.build_parser()._actions if "--csv" in (a.option_strings or [])
    )
    assert action.nargs is None
    assert action.const is None
    assert action.type is None


def test_missing_args_exits_2(sc, capsys):
    assert sc.main([]) == sc.EXIT_USAGE == 2
    err = capsys.readouterr().err
    assert "--metrics" in err or "--csv" in err
    assert "Traceback" not in err


def test_csv_without_value_exits_2(sc, capsys):
    assert sc.main(["--csv"]) == sc.EXIT_USAGE == 2
    err = capsys.readouterr().err
    assert "--csv" in err
    assert "Traceback" not in err


def test_pass_exits_0(sc, capsys):
    code = _run(
        sc,
        _FIXTURES / "scorecard_metrics__pass.txt",
        _FIXTURES / "scorecard_csv__pass.csv",
        "--json",
    )
    captured = capsys.readouterr()
    assert code == sc.EXIT_OK == 0
    payload = json.loads(captured.out)
    assert payload["verdict"] == "pass"
    assert payload["breaches"] == []
    assert payload["attester_effectiveness"] == 1.0
    assert payload["ptc_rate"] == 1.0
    assert payload["missed_proposals"] == 0
    assert payload["slashable_events"] == 0
    assert captured.err == ""


def test_effectiveness_at_99_percent_exits_0(sc, capsys):
    code = _run(
        sc,
        _FIXTURES / "scorecard_metrics__pass.txt",
        _FIXTURES / "scorecard_csv__effectiveness_99.csv",
        "--json",
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["attester_effectiveness"] == 0.99
    assert payload["verdict"] == "pass"


def test_ptc_rate_at_99_percent_exits_0(sc, tmp_path, capsys):
    text = (_FIXTURES / "scorecard_metrics__pass.txt").read_text(encoding="utf-8")
    scrape = tmp_path / "metrics.txt"
    scrape.write_text(
        text.replace(
            'rvc_ptc_attestations_total{status="success"} 100',
            'rvc_ptc_attestations_total{status="success"} 99',
        ),
        encoding="utf-8",
    )
    code = _run(sc, scrape, _FIXTURES / "scorecard_csv__pass.csv", "--json")
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["ptc_rate"] == 0.99
    assert payload["verdict"] == "pass"


def test_effectiveness_below_99_exits_4(sc, capsys):
    code = _run(
        sc,
        _FIXTURES / "scorecard_metrics__pass.txt",
        _FIXTURES / "scorecard_csv__low_effectiveness.csv",
        "--json",
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert code == sc.EXIT_THRESHOLD == 4
    assert payload["verdict"] == "fail"
    assert "attester_effectiveness" in payload["breaches"]
    assert payload["ptc_rate"] == 1.0
    assert payload["missed_proposals"] == 0
    assert "attester_effectiveness" in captured.err
    assert "Traceback" not in captured.err


def test_ptc_rate_below_99_exits_4(sc, capsys):
    code = _run(
        sc,
        _FIXTURES / "scorecard_metrics__ptc_low.txt",
        _FIXTURES / "scorecard_csv__pass.csv",
        "--json",
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert code == sc.EXIT_THRESHOLD == 4
    assert payload["verdict"] == "fail"
    assert "ptc_rate" in payload["breaches"]
    assert payload["ptc_rate"] == 0.98
    assert payload["attester_effectiveness"] == 1.0
    assert "ptc_rate" in captured.err


def test_missed_proposals_exits_4(sc, capsys):
    code = _run(
        sc,
        _FIXTURES / "scorecard_metrics__pass.txt",
        _FIXTURES / "scorecard_csv__missed_proposals.csv",
        "--json",
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert code == sc.EXIT_THRESHOLD == 4
    assert "missed_proposals" in payload["breaches"]
    assert payload["missed_proposals"] == 1
    assert "missed_proposals" in captured.err


@pytest.mark.parametrize(
    "metrics",
    (
        "scorecard_metrics__slashable.txt",
        "scorecard_metrics__blocked.txt",
    ),
)
def test_slashable_event_exits_4(sc, capsys, metrics):
    code = _run(
        sc,
        _FIXTURES / metrics,
        _FIXTURES / "scorecard_csv__pass.csv",
        "--json",
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert code == sc.EXIT_THRESHOLD == 4
    assert "slashable_events" in payload["breaches"]
    assert payload["slashable_events"] > 0
    assert "slashable_events" in captured.err


def test_skipped_no_data_is_not_a_failure(sc, capsys):
    code = _run(
        sc,
        _FIXTURES / "scorecard_metrics__skipped_no_data.txt",
        _FIXTURES / "scorecard_csv__pass.csv",
        "--json",
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert code == sc.EXIT_OK == 0
    assert payload["ptc_rate"] == 1.0
    assert payload["verdict"] == "pass"
    assert captured.err == ""


@pytest.mark.parametrize(
    "name",
    ("rvc_ptc_duties_total", "rvc_ptc_attestations_total"),
)
def test_missing_ptc_family_exits_nonzero_naming_it(sc, tmp_path, capsys, name):
    text = (_FIXTURES / "scorecard_metrics__pass.txt").read_text(encoding="utf-8")
    dropped = _drop_family(text, name)
    assert name not in dropped
    scrape = tmp_path / "metrics.txt"
    scrape.write_text(dropped, encoding="utf-8")
    capsys.readouterr()
    code = _run(sc, scrape, _FIXTURES / "scorecard_csv__pass.csv")
    captured = capsys.readouterr()
    assert code != 0
    assert code == sc.EXIT_ERROR == 1
    assert name in captured.err
    assert "Traceback" not in captured.err
    assert captured.out == ""


def test_missing_both_ptc_families_names_both(sc, tmp_path, capsys):
    text = (_FIXTURES / "scorecard_metrics__pass.txt").read_text(encoding="utf-8")
    dropped = _drop_family(text, "rvc_ptc_duties_total")
    dropped = _drop_family(dropped, "rvc_ptc_attestations_total")
    scrape = tmp_path / "metrics.txt"
    scrape.write_text(dropped, encoding="utf-8")
    code = _run(sc, scrape, _FIXTURES / "scorecard_csv__pass.csv")
    err = capsys.readouterr().err
    assert code == 1
    assert "rvc_ptc_duties_total" in err
    assert "rvc_ptc_attestations_total" in err


def test_missing_metrics_file_exits_2(sc, tmp_path, capsys):
    missing = tmp_path / "no-such-metrics.txt"
    code = _run(sc, missing, _FIXTURES / "scorecard_csv__pass.csv")
    err = capsys.readouterr().err
    assert code == sc.EXIT_USAGE == 2
    assert str(missing) in err or "No such file" in err or "not found" in err.lower()


def _patch_metrics(tmp_path: Path, old: str, new: str) -> Path:
    text = (_FIXTURES / "scorecard_metrics__pass.txt").read_text(encoding="utf-8")
    assert old in text
    path = tmp_path / "metrics.txt"
    path.write_text(text.replace(old, new), encoding="utf-8")
    return path


def _assert_not_pass(code: int, captured, sc) -> None:
    assert code != 0
    assert code == sc.EXIT_ERROR == 1
    assert "verdict pass" not in captured.out
    assert "Traceback" not in captured.err
    if captured.out.strip():
        payload = json.loads(captured.out)
        assert payload.get("verdict") != "pass"


@pytest.mark.parametrize("raw", ("NaN", "+Inf", "-Inf", "-1"))
def test_non_finite_or_negative_ptc_sample_exits_nonzero(
    sc, tmp_path, capsys, raw
):
    scrape = _patch_metrics(
        tmp_path,
        'rvc_ptc_attestations_total{status="success"} 100',
        f'rvc_ptc_attestations_total{{status="success"}} {raw}',
    )
    code = _run(sc, scrape, _FIXTURES / "scorecard_csv__pass.csv", "--json")
    captured = capsys.readouterr()
    _assert_not_pass(code, captured, sc)
    assert "rvc_ptc_attestations_total" in captured.err


@pytest.mark.parametrize("raw", ("NaN", "+Inf", "-Inf", "-1"))
def test_non_finite_or_negative_slashable_exits_nonzero(
    sc, tmp_path, capsys, raw
):
    scrape = _patch_metrics(
        tmp_path,
        "rvc_validators_slashed_total 0",
        f"rvc_validators_slashed_total {raw}",
    )
    code = _run(sc, scrape, _FIXTURES / "scorecard_csv__pass.csv", "--json")
    captured = capsys.readouterr()
    _assert_not_pass(code, captured, sc)
    assert "rvc_validators_slashed_total" in captured.err


def test_csv_nan_effectiveness_exits_nonzero(sc, tmp_path, capsys):
    csv_path = tmp_path / "row.csv"
    csv_path.write_text(
        "attester_effectiveness,proposals.missed\nNaN,0\n", encoding="utf-8"
    )
    code = _run(
        sc, _FIXTURES / "scorecard_metrics__pass.txt", csv_path, "--json"
    )
    captured = capsys.readouterr()
    _assert_not_pass(code, captured, sc)
    assert "attester_effectiveness" in captured.err


def test_csv_negative_missed_exits_nonzero(sc, tmp_path, capsys):
    csv_path = tmp_path / "row.csv"
    csv_path.write_text(
        "attester_effectiveness,proposals.missed\n1.0,-1\n", encoding="utf-8"
    )
    code = _run(
        sc, _FIXTURES / "scorecard_metrics__pass.txt", csv_path, "--json"
    )
    captured = capsys.readouterr()
    _assert_not_pass(code, captured, sc)
    assert "proposals.missed" in captured.err


def test_empty_missed_proposals_exits_nonzero(sc, tmp_path, capsys):
    csv_path = tmp_path / "row.csv"
    csv_path.write_text(
        "attester_effectiveness,proposals.missed\n1.0,\n", encoding="utf-8"
    )
    code = _run(sc, _FIXTURES / "scorecard_metrics__pass.txt", csv_path)
    captured = capsys.readouterr()
    _assert_not_pass(code, captured, sc)
    assert "proposals.missed" in captured.err


@pytest.mark.parametrize(
    "name",
    ("rvc_validators_slashed_total", "rvc_slashing_protection_checks_total"),
)
def test_missing_slashing_family_exits_nonzero(sc, tmp_path, capsys, name):
    text = (_FIXTURES / "scorecard_metrics__pass.txt").read_text(encoding="utf-8")
    scrape = tmp_path / "metrics.txt"
    scrape.write_text(_drop_family(text, name), encoding="utf-8")
    code = _run(sc, scrape, _FIXTURES / "scorecard_csv__pass.csv")
    captured = capsys.readouterr()
    _assert_not_pass(code, captured, sc)
    assert name in captured.err


def test_scheduled_zero_without_skips_exits_nonzero(sc, tmp_path, capsys):
    scrape = _patch_metrics(
        tmp_path,
        'rvc_ptc_duties_total{outcome="scheduled"} 100',
        'rvc_ptc_duties_total{outcome="scheduled"} 0',
    )
    scrape.write_text(
        scrape.read_text(encoding="utf-8").replace(
            'rvc_ptc_duties_total{outcome="skipped_no_data"} 5',
            'rvc_ptc_duties_total{outcome="skipped_no_data"} 0',
        ),
        encoding="utf-8",
    )
    code = _run(sc, scrape, _FIXTURES / "scorecard_csv__pass.csv")
    captured = capsys.readouterr()
    _assert_not_pass(code, captured, sc)
    assert "scheduled=0" in captured.err


def test_metrics_symlink_exits_nonzero(sc, tmp_path, capsys):
    real = tmp_path / "metrics.txt"
    real.write_text(
        (_FIXTURES / "scorecard_metrics__pass.txt").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    link = tmp_path / "metrics.link"
    link.symlink_to(real)
    code = _run(sc, link, _FIXTURES / "scorecard_csv__pass.csv")
    captured = capsys.readouterr()
    _assert_not_pass(code, captured, sc)
    assert "symlink" in captured.err


def test_metrics_fifo_exits_nonzero(sc, tmp_path, capsys):
    fifo = tmp_path / "metrics.fifo"
    os.mkfifo(fifo)
    code = _run(sc, fifo, _FIXTURES / "scorecard_csv__pass.csv")
    captured = capsys.readouterr()
    _assert_not_pass(code, captured, sc)
    assert "regular file" in captured.err
