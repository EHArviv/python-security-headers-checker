# Python Security Headers Checker

A Python security automation tool that checks HTTP security headers for websites, identifies missing protections, calculates a security score, assigns a risk level, and generates CSV/TXT reports.

## Features

- Check HTTP security headers
- Detect missing security protections
- Calculate a security score
- Assign a risk level
- Analyze a single URL
- Analyze multiple URLs from a file
- Generate CSV reports
- Generate TXT summary reports
- Run from the command line

## Security Headers Checked

The tool checks for the following headers:

- Strict-Transport-Security
- Content-Security-Policy
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy

## Project Structure

```text
python-security-headers-checker/
├── src/
│   └── headers_checker.py
├── sample_urls/
│   └── urls.txt
├── reports/
│   └── .gitkeep
├── README.md
├── requirements.txt
└── .gitignore
```

## Installation

Install the required dependency:

```bash
pip install -r requirements.txt
```

## Usage

Check a single URL:

```bash
python src/headers_checker.py https://example.com
```

Check multiple URLs from a file:

```bash
python src/headers_checker.py --file sample_urls/urls.txt
```

## Generated Reports

The script generates the following files locally inside the `reports/` folder:

```text
security_headers_report.csv
security_headers_summary.txt
```

These generated report files are ignored by Git and should not be committed to the repository.

## Example Output

```text
URL: https://example.com

Strict-Transport-Security: Missing
Content-Security-Policy: Missing
X-Frame-Options: Found
X-Content-Type-Options: Found
Referrer-Policy: Found
Permissions-Policy: Missing

Score: 3/6
Risk Level: Medium
```

## Risk Level Logic

The script calculates the risk level based on the number of required headers found.

```text
All headers found      → Low
Most headers found     → Medium
Several headers missing → High
```

## Requirements

This project uses:

- Python 3
- requests

## Skills Demonstrated

- Python automation
- HTTP requests
- Web security basics
- Security header analysis
- CSV report generation
- TXT summary generation
- Command-line arguments
- Risk scoring
- IT/Security automation workflow

## Example Resume Description

Built a Python security automation tool that checks HTTP security headers, identifies missing protections, calculates risk levels, and generates CSV/TXT reports for web security assessment.