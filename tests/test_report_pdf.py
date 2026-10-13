import subprocess
from pathlib import Path

import pytest

from appsec_ai.models import Category, Finding, ScanResult, Severity
from appsec_ai.report_pdf import to_pdf
from appsec_ai.scanner import scan

FIXTURE = Path(__file__).parent / "fixtures" / "llm_app"


def pdf_text(pdf: bytes, tmp_path: Path) -> str:
    path = tmp_path / "r.pdf"
    path.write_bytes(pdf)
    try:
        return subprocess.run(["pdftotext", "-layout", str(path), "-"], capture_output=True, text=True, check=True).stdout
    except FileNotFoundError:
        pytest.skip("pdftotext no instalado")


@pytest.mark.parametrize("lang, title, mapping", [("es", "Informe de seguridad", "Mapeo a marcos de IA"),
                                                  ("en", "Security report", "AI framework mapping")])
def test_pdf_report_in_both_languages(tmp_path, lang, title, mapping):
    result = scan(FIXTURE, engines=["ai-security"])
    pdf = to_pdf(result, lang=lang, target="acme/shop", commit="abc1234def")
    assert pdf.startswith(b"%PDF")
    text = pdf_text(pdf, tmp_path)
    assert title in text and mapping in text and "acme/shop" in text and "abc1234def" in text
    assert "AML.T0050" in text and "eval(answer)" in text


def test_pdf_escapes_markup_from_customer_code(tmp_path):
    evil = Finding(engine="x", rule_id="r", category=Category.SAST, severity=Severity.HIGH,
                   title="<b>x</b> & <font size=90>", message="<para>m</para>", file="a<b>.py", line=1,
                   snippet="if a < b and c > d: pass")
    pdf = to_pdf(ScanResult(target="t", findings=[evil]), lang="es")
    text = pdf_text(pdf, tmp_path)
    assert "<b>x</b> & <font size=90>" in text and "a<b>.py" in text
