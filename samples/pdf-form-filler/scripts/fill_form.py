#!/usr/bin/env python3
"""Fill a PDF form's fields from a JSON file. Usage: fill_form.py IN.pdf VALUES.json OUT.pdf"""
import json
import sys

from pypdf import PdfReader, PdfWriter


def main() -> None:
    if sys.argv[1] == "--list":
        for name in PdfReader(sys.argv[2]).get_fields() or {}:
            print(name)
        return
    source, values_path, target = sys.argv[1:4]
    if source == target:
        sys.exit("refusing to overwrite the input file")
    reader = PdfReader(source)
    writer = PdfWriter()
    writer.append(reader)
    values = json.load(open(values_path))
    for page in writer.pages:
        writer.update_page_form_field_values(page, values)
    with open(target, "wb") as handle:
        writer.write(handle)
    missing = sorted(set(reader.get_fields() or {}) - set(values))
    print(json.dumps({"filled": sorted(values), "unfilled": missing}))


if __name__ == "__main__":
    main()
