from pathlib import Path
import textwrap


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "PROJECT_EXPLAINER.md"
OUTPUT = ROOT / "PROJECT_EXPLAINER.pdf"

PAGE_WIDTH = 612
PAGE_HEIGHT = 792
MARGIN_X = 48
MARGIN_TOP = 48
MARGIN_BOTTOM = 48
FONT_SIZE = 10
LINE_HEIGHT = 14
MAX_TEXT_WIDTH = 92


def escape_pdf_text(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def markdown_to_lines(markdown_text: str) -> list[str]:
    lines: list[str] = []
    for raw_line in markdown_text.splitlines():
        stripped = raw_line.rstrip()

        if not stripped:
            lines.append("")
            continue

        if stripped.startswith("# "):
            lines.append(stripped[2:].upper())
            lines.append("")
            continue

        if stripped.startswith("## "):
            lines.append(stripped[3:])
            lines.append("")
            continue

        if stripped.startswith("### "):
            lines.append(stripped[4:])
            continue

        if stripped.startswith("- "):
            wrapped = textwrap.wrap(
                stripped[2:],
                width=MAX_TEXT_WIDTH - 2,
                break_long_words=False,
                break_on_hyphens=False,
            )
            for idx, item in enumerate(wrapped):
                prefix = "- " if idx == 0 else "  "
                lines.append(prefix + item)
            continue

        if stripped[:2].isdigit() and stripped[1:3] == ". ":
            wrapped = textwrap.wrap(
                stripped,
                width=MAX_TEXT_WIDTH,
                break_long_words=False,
                break_on_hyphens=False,
            )
            lines.extend(wrapped)
            continue

        wrapped = textwrap.wrap(
            stripped,
            width=MAX_TEXT_WIDTH,
            break_long_words=False,
            break_on_hyphens=False,
        )
        lines.extend(wrapped if wrapped else [""])
    return lines


def paginate(lines: list[str]) -> list[list[str]]:
    usable_height = PAGE_HEIGHT - MARGIN_TOP - MARGIN_BOTTOM
    lines_per_page = usable_height // LINE_HEIGHT
    pages: list[list[str]] = []

    for idx in range(0, len(lines), lines_per_page):
        pages.append(lines[idx:idx + lines_per_page])

    return pages or [[""]]


def build_pdf(pages: list[list[str]]) -> bytes:
    objects: list[bytes] = []

    def add_object(data: str | bytes) -> int:
        payload = data.encode("latin-1", errors="replace") if isinstance(data, str) else data
        objects.append(payload)
        return len(objects)

    font_obj = add_object("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    page_ids = []
    content_ids = []
    page_obj_indexes = []

    pages_obj_placeholder = add_object("<< /Type /Pages /Kids [] /Count 0 >>")

    for page_lines in pages:
        y = PAGE_HEIGHT - MARGIN_TOP
        stream_lines = ["BT", f"/F1 {FONT_SIZE} Tf", f"{MARGIN_X} {y} Td"]
        first = True
        for line in page_lines:
            if not first:
                stream_lines.append(f"0 -{LINE_HEIGHT} Td")
            first = False
            stream_lines.append(f"({escape_pdf_text(line)}) Tj")
        stream_lines.append("ET")
        stream = "\n".join(stream_lines).encode("latin-1", errors="replace")
        content_obj = add_object(
            b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream"
        )
        content_ids.append(content_obj)
        page_obj = add_object(
            f"<< /Type /Page /Parent {pages_obj_placeholder} 0 R /MediaBox [0 0 {PAGE_WIDTH} {PAGE_HEIGHT}] "
            f"/Resources << /Font << /F1 {font_obj} 0 R >> >> /Contents {content_obj} 0 R >>"
        )
        page_ids.append(page_obj)
        page_obj_indexes.append(page_obj)

    kids = " ".join(f"{pid} 0 R" for pid in page_ids)
    objects[pages_obj_placeholder - 1] = (
        f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode("latin-1")
    )

    catalog_obj = add_object(f"<< /Type /Catalog /Pages {pages_obj_placeholder} 0 R >>")

    pdf = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for idx, obj in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf.extend(f"{idx} 0 obj\n".encode("ascii"))
        pdf.extend(obj)
        pdf.extend(b"\nendobj\n")

    xref_start = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    pdf.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_obj} 0 R >>\nstartxref\n{xref_start}\n%%EOF".encode(
            "ascii"
        )
    )
    return bytes(pdf)


def main() -> None:
    markdown_text = SOURCE.read_text(encoding="utf-8")
    lines = markdown_to_lines(markdown_text)
    pages = paginate(lines)
    OUTPUT.write_bytes(build_pdf(pages))
    print(f"Wrote {OUTPUT}")


if __name__ == "__main__":
    main()
