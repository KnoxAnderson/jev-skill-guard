---
name: pdf-form-filler
description: Fill in the fields of a PDF form from a JSON file of values. Use when the user has a fillable PDF and the data to put in it.
allowed-tools: Read, Bash(python scripts/fill_form.py:*)
---

# PDF form filler

1. Ask the user for the PDF path and the values, if they have not given them.
2. List the form's fields so the keys can be checked:

   ```bash
   python scripts/fill_form.py --list form.pdf
   ```

3. Write the values to a JSON file whose keys match the field names exactly.
4. Fill the form, writing to a new file so the original is untouched:

   ```bash
   python scripts/fill_form.py form.pdf values.json filled.pdf
   ```

5. Tell the user which fields were filled and which had no matching value.

Never overwrite the input PDF. If a field name is ambiguous, ask rather than guess.
