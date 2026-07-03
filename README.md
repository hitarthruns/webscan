# WebScan

WebScan is a small Python vulnerability scanner that crawls a target site, tests discovered URLs and forms, and reports potential:

- SQL injection issues
- Cross-site scripting (XSS)
- Directory traversal issues

It prints a console summary and generates an HTML report at `report.html`.

## Requirements

- Python 3.10+
- `requests`
- `beautifulsoup4`

## Installation

Install the Python dependencies:

```bash
pip install requests beautifulsoup4
```

## Usage

Run the scanner from the project root:

```bash
python scanner.py <target_url> [max_pages]
```

Examples:

```bash
python scanner.py http://example.com
python scanner.py http://example.com 100
```

`max_pages` is optional and defaults to `50`.

## Output

- Console output shows crawl progress and any findings.
- `report.html` is overwritten with the latest scan results.

## Payloads

Payload lists live in the `payloads/` directory:

- `payloads/sqli.txt`
- `payloads/xss.txt`
- `payloads/traversal.txt`

## Project Layout

- `scanner.py` - main scanner entry point
- `crawler.py` - site crawler
- `sqli.py` - SQL injection checks
- `xss.py` - XSS checks
- `traversal.py` - directory traversal checks
- `utils.py` - shared helpers
- `report.html` - generated scan report

## Note

Only scan systems you own or have permission to test.