"""Convert PQgate SARIF into a GitLab SAST security report (schema 15.0.7).

Pure translation — no network, no re-analysis. Deterministic ids so GitLab can track
a finding across pipelines.
"""
import datetime
import hashlib
import json
import sys

SCHEMA = ("https://gitlab.com/gitlab-org/security-products/security-report-schemas/"
          "-/raw/v15.0.7/dist/sast-report-format.json")

SEVERITY = {"error": "Critical", "warning": "Medium", "note": "Info", "none": "Info"}


def convert(sarif):
    run = sarif["runs"][0]
    driver = run["tool"]["driver"]
    rules = {r["id"]: r for r in driver.get("rules", [])}

    vulnerabilities = []
    for result in run.get("results", []):
        rule = rules.get(result["ruleId"], {})
        loc = result["locations"][0]["physicalLocation"]
        path = loc["artifactLocation"]["uri"]
        line = loc["region"]["startLine"]
        fingerprint = (result.get("partialFingerprints", {}).get("pqgate/v1")
                       or hashlib.sha256((result["ruleId"] + path + str(line)).encode()).hexdigest()[:16])
        vulnerabilities.append({
            "id": hashlib.sha256((result["ruleId"] + path + str(line)).encode()).hexdigest(),
            "category": "sast",
            "name": rule.get("shortDescription", {}).get("text", result["ruleId"]),
            "message": result["message"]["text"],
            "description": rule.get("help", {}).get("text", ""),
            "cve": "pqgate:" + result["ruleId"] + ":" + fingerprint,
            "severity": SEVERITY.get(result.get("level", "note"), "Info"),
            "scanner": {"id": "pqgate", "name": "PQgate"},
            "location": {"file": path, "start_line": line, "end_line": line},
            "identifiers": [{
                "type": "pqgate_rule",
                "name": "PQgate " + result["ruleId"],
                "value": result["ruleId"],
            }],
            "flags": [],
        })

    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    return {
        "version": "15.0.7",
        "schema": SCHEMA,
        "scan": {
            "start_time": now,
            "end_time": now,
            "status": "success",
            "type": "sast",
            "analyzer": {"id": "pqgate", "name": "PQgate",
                         "version": driver.get("version", "0"),
                         "vendor": {"name": "PQgate"}},
            "scanner": {"id": "pqgate", "name": "PQgate",
                        "version": driver.get("version", "0"),
                        "vendor": {"name": "PQgate"}},
        },
        "vulnerabilities": vulnerabilities,
    }


def main(argv):
    if len(argv) != 3:
        print("usage: sarif_to_gitlab.py <in.sarif> <out.json>", file=sys.stderr)
        return 2
    with open(argv[1], encoding="utf-8") as fh:
        sarif = json.load(fh)
    with open(argv[2], "w", encoding="utf-8") as fh:
        json.dump(convert(sarif), fh, indent=2)
    print("gitlab security report -> " + argv[2])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
