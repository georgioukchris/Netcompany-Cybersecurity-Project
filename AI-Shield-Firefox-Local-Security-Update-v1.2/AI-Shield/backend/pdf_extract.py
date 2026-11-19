"""PDF text extraction for the DLP scanner.

The file is processed in memory only: neither its bytes, its text nor its file name
are written to disk, the database or the logs. Anything that cannot be fully inspected
is reported as such, so the caller can fail closed instead of letting it through.
"""
import io
import logging

from pypdf import PdfReader

MAX_PDF_BYTES = 10 * 1024 * 1024      # 10 MB
MAX_PDF_PAGES = 200
MAX_PDF_CHARS = 60_000                # what the scanner handles in a couple of seconds

# pypdf logs warnings that can quote fragments of a malformed file: keep them out of the logs.
logging.getLogger("pypdf").setLevel(logging.ERROR)


class PdfInspectionError(Exception):
    """The PDF cannot be inspected completely. `code` is machine-readable."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def is_pdf(data: bytes) -> bool:
    # The header may be preceded by a little junk; readers accept it in the first 1 KB.
    return b"%PDF-" in data[:1024]


def extract_pdf_text(data: bytes) -> dict:
    """Return {"text", "pages"}. Raises PdfInspectionError when the file cannot be
    inspected in full (encrypted, too many pages, too much text, corrupt)."""
    if len(data) > MAX_PDF_BYTES:
        raise PdfInspectionError("too_large", f"Το PDF ξεπερνά τα {MAX_PDF_BYTES // (1024 * 1024)} MB.")
    if not is_pdf(data):
        raise PdfInspectionError("not_pdf", "Το αρχείο δεν είναι PDF.")
    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
        if reader.is_encrypted:
            # PDFs with an empty user password (print/copy restrictions only) can still be read.
            try:
                if not reader.decrypt(""):
                    raise PdfInspectionError("encrypted", "Το PDF προστατεύεται με κωδικό και δεν μπορεί να ελεγχθεί.")
            except PdfInspectionError:
                raise
            except Exception as exc:
                raise PdfInspectionError("encrypted", "Το PDF είναι κρυπτογραφημένο και δεν μπορεί να ελεγχθεί.") from exc
        pages = len(reader.pages)
        if pages > MAX_PDF_PAGES:
            raise PdfInspectionError("too_many_pages", f"Το PDF έχει {pages} σελίδες (όριο {MAX_PDF_PAGES}).")
        parts, total = [], 0
        for page in reader.pages:
            text = page.extract_text() or ""
            total += len(text)
            if total > MAX_PDF_CHARS:
                raise PdfInspectionError(
                    "too_much_text",
                    f"Το PDF έχει πάνω από {MAX_PDF_CHARS:,} χαρακτήρες κειμένου και δεν μπορεί να ελεγχθεί ολόκληρο.".replace(",", "."))
            parts.append(text)
    except PdfInspectionError:
        raise
    except Exception as exc:
        raise PdfInspectionError("unreadable", "Το PDF είναι κατεστραμμένο ή δεν μπορεί να διαβαστεί.") from exc
    text = "\n\n".join(p.strip() for p in parts if p and p.strip())
    return {"text": text, "pages": pages}
