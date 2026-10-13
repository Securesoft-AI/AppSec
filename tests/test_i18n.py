"""Inglés y español en GitHub, informes y panel (RF-4.6)."""
import glob
from pathlib import Path

import yaml

from appsec_ai import report
from appsec_ai.engines.ai_common import RULES
from appsec_ai.i18n import RULES_EN, localize
from appsec_ai.scanner import scan
from appsec_ai.service import render

FIXTURE = Path(__file__).parent / "fixtures" / "llm_app"


def test_every_rule_has_an_english_text():
    ids = set(RULES)
    for f in glob.glob(str(Path(__file__).parents[1] / "src/appsec_ai/rules/*/*.yaml")):
        ids |= {r["id"] for r in yaml.safe_load(open(f))["rules"]}
    assert ids == set(RULES_EN)


def test_dynamic_titles_keep_their_variable_part():
    result = scan(FIXTURE, engines=["ai-security"])
    tool = next(f for f in result.findings if f.rule_id == "llm06-excessive-agency-tool")
    title, message = localize(tool, "en")
    assert title.startswith("Agent tool '") and "dangerous actions" in title
    assert "Sensitive operations detected:" in message
    assert localize(tool, "es") == (tool.title, tool.message)


def test_github_outputs_and_markdown_report_in_english():
    result = scan(FIXTURE, engines=["ai-security"])
    title, summary, _ = render.check_output(result, full_scan=False, lang="en")
    assert "security finding" in title and "changed by this PR" in summary
    comment = render.pr_comment(result, lang="en")
    assert "Files changed" in comment and "LLM output executed as code or command" in comment
    assert render.fix_actions(result, "en") == []  # sin triage no hay botón
    md = report.to_markdown(result, lang="en")
    assert "# Security report" in md and "## AI framework mapping" in md and "Informe" not in md
    annotations = render.annotations(render.visible(result), "en")
    assert all("Salida del LLM" not in a["title"] for a in annotations)
