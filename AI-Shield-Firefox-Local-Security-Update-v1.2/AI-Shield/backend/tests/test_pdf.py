"""PDF attachments: text extraction + the same DLP policy as prompts. Synthetic data only.
Run: python -m pytest backend/tests  (or: python backend/tests/test_pdf.py)"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pdf_extract import PdfInspectionError, extract_pdf_text, is_pdf  # noqa: E402
from policy import evaluate_policy  # noqa: E402
from scanner import scan_prompt  # noqa: E402


def make_pdf(lines, pages=1):
    """Minimal valid PDF (Helvetica, Latin text) with a correct xref table."""
    objs = ["<< /Type /Catalog /Pages 2 0 R >>", None,
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    kids = []
    for _ in range(pages):
        text = " ".join(f"({line}) Tj 0 -16 Td" for line in lines)
        stream = f"BT /F1 11 Tf 50 780 Td {text} ET"
        objs.append(f"<< /Length {len(stream)} >>\nstream\n{stream}\nendstream")
        objs.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
                    f"/Resources << /Font << /F1 3 0 R >> >> /Contents {len(objs)} 0 R >>")
        kids.append(f"{len(objs)} 0 R")
    objs[1] = f"<< /Type /Pages /Kids [{' '.join(kids)}] /Count {pages} >>"
    out, offsets = bytearray(b"%PDF-1.4\n"), []
    for i, body in enumerate(objs, 1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n{body}\nendobj\n".encode("latin-1")
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


def decide(data):
    text = extract_pdf_text(data)["text"]
    scan = scan_prompt(text)
    return text, scan, evaluate_policy(scan["findings"])["action"]


def test_redact_values_found_at_correct_offsets():
    text, scan, action = decide(make_pdf(["Client data", "AFM: 094014201", "Email: j.smith@example.com"]))
    assert action == "REDACT"
    values = {text[e["start"]:e["end"]] for e in scan["entities"]}
    assert "094014201" in values and "j.smith@example.com" in values


def test_credentials_are_blocked():
    _, _, action = decide(make_pdf(["Server login", "password: Summer2026!x"]))
    assert action == "BLOCK"


def test_clean_document_is_allowed():
    _, scan, action = decide(make_pdf(["Team meeting agenda", "Tuesday 10:00 sprint review"]))
    assert action == "ALLOW" and not scan["findings"]


def test_multi_page_text_is_fully_read():
    text, _, _ = decide(make_pdf(["Page text", "contact: a.b@example.com"], pages=5))
    assert text.count("a.b@example.com") == 5


def test_not_a_pdf_and_too_large_fail_closed():
    assert not is_pdf(b"PK\x03\x04zip")
    for data, code in ((b"PK\x03\x04zip", "not_pdf"), (b"%PDF-1.4\n" + b"0" * (10 * 1024 * 1024 + 1), "too_large"),
                       (b"%PDF-1.4\n garbage", "unreadable")):
        try:
            extract_pdf_text(data)
            assert False, code
        except PdfInspectionError as exc:
            assert exc.code == code


def test_too_much_text_fails_closed():
    line = "General contract terms without personal data, repeated for volume." * 3
    try:
        extract_pdf_text(make_pdf([line] * 40, pages=12))
        assert False
    except PdfInspectionError as exc:
        assert exc.code == "too_much_text"


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
