# Regex Data Extraction

A small Python program that reads a text file, finds different kinds of data
using regex, and saves the results as JSON.

## How to run

```bash
python src/main.py
```

Needs Python 3. No extra libraries.

It reads `input/raw-text.txt` and writes the results to
`output/sample-output.json`.

## Folders

```
input/raw-text.txt          the text we read
src/main.py                 the program
output/sample-output.json   the results (overwritten on every run)
```

## What it finds

- **Emails** - with ALU tags: `@alueducation.com`, `@alumni.alueducation.com`, `@si.alueducation.com`
- **Credit cards** - validated with the Luhn algorithm
- **URLs** - `http` and `https` only
- **Phone numbers**
- Times, HTML tags, hashtags, currency

## Security

The input is treated as untrusted:

- File size limited to 2 MB
- Only `http` / `https` URLs are kept (ignores `javascript:`, `data:`, etc.)
- Credit cards are Luhn-checked; failures are flagged, not silently dropped
- Emails, cards, and phones are **masked** in the output
- `<script>` and `<iframe>` tags are marked as dangerous
- Nothing from the input is ever `eval`'d or run in a shell
