import importlib.util
from pathlib import Path

from appsec_ai.models import Severity, Triage, Verdict

spec = importlib.util.spec_from_file_location(
    "run_eval", Path(__file__).parents[1] / "evals" / "triage" / "run_eval.py")
run_eval = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run_eval)


def test_labels_match_scanner_findings():
    # Si falla, una regla cambió: revisa los casos o evals/triage/labels.json.
    assert run_eval.check_coverage(run_eval.detect(), run_eval.load_labels()) == ([], [])


def test_perfect_triage_scores_100_and_dismissing_real_issue_is_counted():
    labels = run_eval.load_labels()
    findings = run_eval.detect()
    for f in findings:
        label = labels[run_eval.key(f)]
        f.triage = Triage(verdict=Verdict(label["expected"]),
                          severity=Severity(label.get("severity", ["info"])[0]),
                          confidence=0.9, explanation="", exploit_scenario="", fix="", fixed_code="")
    summary = run_eval.summarize([run_eval.score(findings, labels)])
    assert summary["real_dismissed"] == 0
    assert summary["verdict_ok_pct"] == summary["fp_rejected_pct"] == summary["severity_ok_pct"] == 100.0

    bad = next(f for f in findings if run_eval.key(f).startswith("tp_injection_comment.py:llm05"))
    bad.triage = bad.triage.model_copy(update={"verdict": Verdict.FALSE_POSITIVE})
    summary = run_eval.summarize([run_eval.score(findings, labels)])
    assert summary["real_dismissed"] == 1
