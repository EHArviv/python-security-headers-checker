# Python Security Headers Checker

A Python security automation tool that checks HTTP security headers for websites, identifies missing protections, calculates security scores, assigns risk levels, and generates multiple report formats for IT, Security, SOC, and SIEM workflows.

## Features

- Check HTTP security headers
- Detect missing security protections
- Calculate a security score
- Assign a risk level
- Analyze a single URL
- Analyze multiple URLs from a file
- Generate CSV reports
- Generate TXT summary reports
- Generate JSON reports
- Generate security findings
- Generate NDJSON events for SIEM-style ingestion
- Provide recommendations for missing headers
- Run from the command line

## Security Headers Checked

The tool checks for the following HTTP security headers:

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
security_headers_report.json
findings.json
events.ndjson
```

These generated report files are ignored by Git and should not be committed to the repository.

## Report Types

### CSV Report

```text
security_headers_report.csv
```

Used for spreadsheet-based review, filtering, sorting, and manual analysis.

### TXT Summary

```text
security_headers_summary.txt
```

Used for a human-readable summary of the scan results.

### JSON Report

```text
security_headers_report.json
```

Used for automation, dashboards, APIs, or integration with other tools.

### Findings JSON

```text
findings.json
```

Used to represent security findings in a structured format.

Each finding includes:

- Finding ID
- Finding name
- Severity
- Target URL
- Details
- Recommendation

### NDJSON Events

```text
events.ndjson
```

Used for SIEM-style event ingestion.

Each line is a separate JSON event.

## Example Console Output

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

## Example JSON Report Structure

```json
{
  "tool_name": "Python Security Headers Checker",
  "report_type": "web_security_headers_assessment",
  "generated_at": "2026-06-18T13:00:00+00:00",
  "summary": {
    "total_targets": 3,
    "high_risk": 1,
    "medium_risk": 2,
    "low_risk": 0,
    "unknown_risk": 0
  },
  "results": [
    {
      "url": "https://example.com",
      "error": null,
      "score": 3,
      "total_headers": 6,
      "risk_level": "Medium",
      "missing_headers": [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "Permissions-Policy"
      ]
    }
  ]
}
```

## Example Finding

```json
{
  "id": "FINDING-001",
  "name": "Missing Content-Security-Policy",
  "severity": "Medium",
  "target": "https://example.com",
  "details": "The Content-Security-Policy header was not found in the HTTP response.",
  "recommendation": "Implement a restrictive Content-Security-Policy to reduce XSS risk."
}
```

## Example NDJSON Event

```json
{"timestamp":"2026-06-18T13:00:00+00:00","event_type":"missing_security_header","target":"https://example.com","header":"Content-Security-Policy","severity":"Medium","message":"Missing security header: Content-Security-Policy"}
```

## Risk Level Logic

The script calculates the risk level based on the number of required headers found.

```text
All headers found       → Low
Most headers found      → Medium
Several headers missing → High
```

## Header Recommendations

The tool provides recommendations for missing headers, for example:

| Header | Recommendation |
|---|---|
| Strict-Transport-Security | Enable HSTS to force HTTPS connections. |
| Content-Security-Policy | Implement a restrictive Content-Security-Policy to reduce XSS risk. |
| X-Frame-Options | Set X-Frame-Options to DENY or SAMEORIGIN to reduce clickjacking risk. |
| X-Content-Type-Options | Set X-Content-Type-Options to nosniff. |
| Referrer-Policy | Set a strict Referrer-Policy such as strict-origin-when-cross-origin. |
| Permissions-Policy | Restrict browser features such as camera, microphone, and geolocation. |

## SOC / SIEM Outputs

This project generates multiple output formats commonly used in security operations:

- CSV for spreadsheet-based review
- TXT for human-readable summaries
- JSON for automation, dashboards, and APIs
- `findings.json` for structured security assessment findings
- `events.ndjson` for SIEM/log ingestion workflows

## Requirements

This project uses:

- Python 3
- requests

## Skills Demonstrated

- Python automation
- HTTP requests
- Web security basics
- HTTP security header analysis
- CSV report generation
- TXT summary generation
- JSON report generation
- NDJSON event generation
- Security finding structure
- Command-line arguments
- Risk scoring
- SOC/SIEM-friendly output formats
- IT/Security automation workflow

## Example Resume Description

Built a Python security automation tool that checks HTTP security headers, identifies missing protections, calculates risk levels, provides remediation recommendations, and generates CSV/TXT/JSON/NDJSON reports for web security assessment and SOC/SIEM workflows.