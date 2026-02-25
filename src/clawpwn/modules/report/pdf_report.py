"""PDF report generation helper."""

from datetime import datetime
from pathlib import Path


def generate_pdf_note(report_dir: Path, html_file: Path) -> Path:
    """Create PDF conversion note and return HTML file path for compatibility."""
    pdf_file = report_dir / f"pentest_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

    note = f"""PDF Report Generation

The HTML report has been generated: {html_file.name}

To convert to PDF, you can use:
- Chrome: Open HTML and print to PDF
- wkhtmltopdf: wkhtmltopdf {html_file.name} {pdf_file.name}
- WeasyPrint: python -m weasyprint {html_file.name} {pdf_file.name}

For automatic PDF generation, install weasyprint:
  pip install weasyprint
"""

    pdf_file.with_suffix(".txt").write_text(note)
    return html_file
