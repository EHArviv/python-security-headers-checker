import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests


REQUIRED_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


HEADER_RECOMMENDATIONS = {
    "Strict-Transport-Security": "Enable HSTS to force HTTPS connections.",
    "Content-Security-Policy": "Implement a restrictive Content-Security-Policy to reduce XSS risk.",
    "X-Frame-Options": "Set X-Frame-Options to DENY or SAMEORIGIN to reduce clickjacking risk.",
    "X-Content-Type-Options": "Set X-Content-Type-Options to nosniff.",
    "Referrer-Policy": "Set a strict Referrer-Policy such as strict-origin-when-cross-origin.",
    "Permissions-Policy": "Restrict browser features such as camera, microphone, and geolocation.",
}


def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        return "https://" + url

    return url


def calculate_risk_level(score, total):
    if score == total:
        return "Low"
    elif score >= total - 2:
        return "Medium"
    else:
        return "High"


def check_headers(url):
    url = normalize_url(url)

    try:
        response = requests.get(url, timeout=10)
    except requests.RequestException as error:
        return {
            "url": url,
            "error": str(error),
            "headers": {},
            "score": 0,
            "total_headers": len(REQUIRED_HEADERS),
            "risk_level": "Unknown",
            "missing_headers": [],
        }

    found_headers = {}

    for header in REQUIRED_HEADERS:
        found_headers[header] = header in response.headers

    missing_headers = [
        header for header, is_found in found_headers.items() if not is_found
    ]

    score = sum(1 for is_found in found_headers.values() if is_found)
    risk_level = calculate_risk_level(score, len(REQUIRED_HEADERS))

    return {
        "url": url,
        "error": None,
        "headers": found_headers,
        "score": score,
        "total_headers": len(REQUIRED_HEADERS),
        "risk_level": risk_level,
        "missing_headers": missing_headers,
    }


def print_result(result):
    print("=" * 60)
    print(f"URL: {result['url']}")

    if result["error"]:
        print(f"Error: {result['error']}")
        return

    print()

    for header, is_found in result["headers"].items():
        status = "Found" if is_found else "Missing"
        print(f"{header}: {status}")

    print()
    print(f"Score: {result['score']}/{result['total_headers']}")
    print(f"Risk Level: {result['risk_level']}")


def create_finding_id(index):
    return f"FINDING-{index:03d}"


def get_header_severity(header):
    if header in ["Content-Security-Policy", "Strict-Transport-Security"]:
        return "Medium"

    if header in ["X-Frame-Options", "Permissions-Policy"]:
        return "Low"

    return "Low"


def build_findings(results):
    findings = []
    finding_index = 1

    for result in results:
        if result["error"]:
            findings.append(
                {
                    "id": create_finding_id(finding_index),
                    "name": "URL Check Failed",
                    "severity": "Info",
                    "target": result["url"],
                    "details": result["error"],
                    "recommendation": "Verify the URL, DNS resolution, network connectivity, and TLS configuration.",
                }
            )
            finding_index += 1
            continue

        for header in result["missing_headers"]:
            findings.append(
                {
                    "id": create_finding_id(finding_index),
                    "name": f"Missing {header}",
                    "severity": get_header_severity(header),
                    "target": result["url"],
                    "details": f"The {header} header was not found in the HTTP response.",
                    "recommendation": HEADER_RECOMMENDATIONS.get(
                        header,
                        "Review and implement the missing security header.",
                    ),
                }
            )
            finding_index += 1

    return findings


def build_summary(results):
    summary = {
        "total_targets": len(results),
        "high_risk": 0,
        "medium_risk": 0,
        "low_risk": 0,
        "unknown_risk": 0,
    }

    for result in results:
        risk = result["risk_level"]

        if risk == "High":
            summary["high_risk"] += 1
        elif risk == "Medium":
            summary["medium_risk"] += 1
        elif risk == "Low":
            summary["low_risk"] += 1
        else:
            summary["unknown_risk"] += 1

    return summary


def save_csv_report(results):
    reports_folder = Path("reports")
    reports_folder.mkdir(exist_ok=True)

    report_file = reports_folder / "security_headers_report.csv"

    with report_file.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        writer.writerow(
            [
                "url",
                "score",
                "total_headers",
                "risk_level",
                "missing_headers",
                "error",
            ]
        )

        for result in results:
            writer.writerow(
                [
                    result["url"],
                    result["score"],
                    result["total_headers"],
                    result["risk_level"],
                    ", ".join(result["missing_headers"]),
                    result["error"] or "",
                ]
            )

    print(f"CSV report created: {report_file}")


def save_txt_summary(results, findings):
    reports_folder = Path("reports")
    reports_folder.mkdir(exist_ok=True)

    report_file = reports_folder / "security_headers_summary.txt"
    summary = build_summary(results)

    with report_file.open("w", encoding="utf-8") as file:
        file.write("Security Headers Summary Report\n")
        file.write("-------------------------------\n\n")

        file.write("Summary\n")
        file.write("-------\n")
        file.write(f"Total targets: {summary['total_targets']}\n")
        file.write(f"High risk: {summary['high_risk']}\n")
        file.write(f"Medium risk: {summary['medium_risk']}\n")
        file.write(f"Low risk: {summary['low_risk']}\n")
        file.write(f"Unknown risk: {summary['unknown_risk']}\n")
        file.write(f"Total findings: {len(findings)}\n\n")

        for result in results:
            file.write(f"URL: {result['url']}\n")

            if result["error"]:
                file.write(f"Error: {result['error']}\n\n")
                continue

            file.write(f"Score: {result['score']}/{result['total_headers']}\n")
            file.write(f"Risk Level: {result['risk_level']}\n")

            if result["missing_headers"]:
                file.write("Missing Headers:\n")

                for header in result["missing_headers"]:
                    recommendation = HEADER_RECOMMENDATIONS.get(
                        header,
                        "Review and implement the missing security header.",
                    )
                    file.write(f"- {header}: {recommendation}\n")
            else:
                file.write("All required headers were found.\n")

            file.write("\n")

    print(f"TXT summary created: {report_file}")


def save_json_report(results):
    reports_folder = Path("reports")
    reports_folder.mkdir(exist_ok=True)

    report_file = reports_folder / "security_headers_report.json"
    summary = build_summary(results)

    data = {
        "tool_name": "Python Security Headers Checker",
        "report_type": "web_security_headers_assessment",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "results": results,
    }

    with report_file.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)

    print(f"JSON report created: {report_file}")


def save_findings_json(findings):
    reports_folder = Path("reports")
    reports_folder.mkdir(exist_ok=True)

    report_file = reports_folder / "findings.json"

    with report_file.open("w", encoding="utf-8") as file:
        json.dump(findings, file, indent=2)

    print(f"Findings JSON created: {report_file}")


def save_events_ndjson(results):
    reports_folder = Path("reports")
    reports_folder.mkdir(exist_ok=True)

    report_file = reports_folder / "events.ndjson"

    with report_file.open("w", encoding="utf-8") as file:
        for result in results:
            if result["error"]:
                event = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "event_type": "url_check_failed",
                    "target": result["url"],
                    "severity": "Info",
                    "message": result["error"],
                }
                file.write(json.dumps(event) + "\n")
                continue

            for header in result["missing_headers"]:
                event = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "event_type": "missing_security_header",
                    "target": result["url"],
                    "header": header,
                    "severity": get_header_severity(header),
                    "message": f"Missing security header: {header}",
                    "recommendation": HEADER_RECOMMENDATIONS.get(
                        header,
                        "Review and implement the missing security header.",
                    ),
                }
                file.write(json.dumps(event) + "\n")

    print(f"NDJSON events created: {report_file}")


def load_urls_from_file(file_path):
    path = Path(file_path)

    if not path.exists():
        print(f"Error: file not found: {file_path}")
        return []

    urls = []

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            url = line.strip()

            if url and not url.startswith("#"):
                urls.append(url)

    return urls


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("python src/headers_checker.py <url>")
        print("python src/headers_checker.py --file sample_urls/urls.txt")
        return

    results = []

    if sys.argv[1] == "--file":
        if len(sys.argv) < 3:
            print("Error: missing file path")
            return

        urls = load_urls_from_file(sys.argv[2])

        for url in urls:
            result = check_headers(url)
            results.append(result)
            print_result(result)

    else:
        url = sys.argv[1]
        result = check_headers(url)
        results.append(result)
        print_result(result)

    findings = build_findings(results)

    save_csv_report(results)
    save_txt_summary(results, findings)
    save_json_report(results)
    save_findings_json(findings)
    save_events_ndjson(results)


if __name__ == "__main__":
    main()
