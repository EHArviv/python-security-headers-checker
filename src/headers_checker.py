import csv
import sys
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


def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        return "https://" + url

    return url


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
            "risk_level": "Unknown",
        }

    found_headers = {}

    for header in REQUIRED_HEADERS:
        found_headers[header] = header in response.headers

    score = sum(1 for is_found in found_headers.values() if is_found)
    risk_level = calculate_risk_level(score, len(REQUIRED_HEADERS))

    return {
        "url": url,
        "error": None,
        "headers": found_headers,
        "score": score,
        "risk_level": risk_level,
    }


def calculate_risk_level(score, total):
    if score == total:
        return "Low"
    elif score >= total - 2:
        return "Medium"
    else:
        return "High"


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
    print(f"Score: {result['score']}/{len(REQUIRED_HEADERS)}")
    print(f"Risk Level: {result['risk_level']}")


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
                "risk_level",
                "missing_headers",
                "error",
            ]
        )

        for result in results:
            if result["error"]:
                writer.writerow(
                    [
                        result["url"],
                        0,
                        "Unknown",
                        "",
                        result["error"],
                    ]
                )
                continue

            missing_headers = [
                header for header, is_found in result["headers"].items() if not is_found
            ]

            writer.writerow(
                [
                    result["url"],
                    result["score"],
                    result["risk_level"],
                    ", ".join(missing_headers),
                    "",
                ]
            )

    print(f"\nCSV report created: {report_file}")


def save_txt_summary(results):
    reports_folder = Path("reports")
    reports_folder.mkdir(exist_ok=True)

    report_file = reports_folder / "security_headers_summary.txt"

    with report_file.open("w", encoding="utf-8") as file:
        file.write("Security Headers Summary Report\n")
        file.write("-------------------------------\n\n")

        for result in results:
            file.write(f"URL: {result['url']}\n")

            if result["error"]:
                file.write(f"Error: {result['error']}\n\n")
                continue

            file.write(f"Score: {result['score']}/{len(REQUIRED_HEADERS)}\n")
            file.write(f"Risk Level: {result['risk_level']}\n")

            missing_headers = [
                header for header, is_found in result["headers"].items() if not is_found
            ]

            if missing_headers:
                file.write("Missing Headers:\n")
                for header in missing_headers:
                    file.write(f"- {header}\n")
            else:
                file.write("All required headers were found.\n")

            file.write("\n")

    print(f"TXT summary created: {report_file}")


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

    save_csv_report(results)
    save_txt_summary(results)


if __name__ == "__main__":
    main()
