import json
import subprocess
import os

def scan_code(file_path, language):
    results = {
        "header": "--- Security Scan Report ---",
        "run_started": "",
        "filename": os.path.basename(file_path),
        "language": language,
        "issues": [],
        "metrics": {
            "total_issues": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "lines_of_code": 0
        }
    }

    try:
        if language == "python":
            output = subprocess.run(
                ["bandit", "-r", file_path, "-f", "json"], 
                capture_output=True, 
                text=True,
                timeout=30
            )
            if output.returncode not in [0, 1]:  # Bandit returns 1 when issues found
                results["error"] = f"Bandit scan failed: {output.stderr}"
                return results
            
            try:
                scan_data = json.loads(output.stdout)
                return parse_bandit_results(results, scan_data, file_path)
            
            except json.JSONDecodeError:
                results["error"] = "Failed to parse Bandit scan results."
                return results

        elif language == "php":
            output = subprocess.run(
                ["phpstan", "analyse", "--error-format=json", file_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            try:
                scan_data = json.loads(output.stdout)
                return parse_phpstan_results(results, scan_data, file_path)
            except json.JSONDecodeError:
                results["error"] = "Failed to parse PHPStan scan results."
                return results

        elif language == "javascript":
            output = subprocess.run(
                ["eslint", "-f", "json", file_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            try:
                scan_data = json.loads(output.stdout)
                return parse_eslint_results(results, scan_data, file_path)
            except json.JSONDecodeError:
                results["error"] = "Failed to parse ESLint scan results."
                return results

    except subprocess.TimeoutExpired:
        results["error"] = "Scan timed out after 30 seconds."
        return results
    except Exception as e:
        results["error"] = f"Unexpected error: {str(e)}"
        return results

def parse_bandit_results(results, scan_data, file_path):
    results["run_started"] = scan_data.get("generated_at", "")
    results["metrics"]["lines_of_code"] = scan_data.get("metrics", {}).get(file_path, {}).get("loc", 0)
    
    for issue in scan_data.get("results", []):
        severity = issue["issue_severity"].upper()
        confidence = issue["issue_confidence"].capitalize()
        
        results["issues"].append({
            "test_id": issue["test_id"],
            "test_name": issue["test_name"],
            "severity": severity,
            "confidence": confidence,
            "cwe": issue["issue_cwe"]["id"],
            "cwe_link": issue["issue_cwe"]["link"],
            "location": issue["filename"],
            "line": issue["line_number"],
            "code": issue["code"],
            "description": issue["issue_text"],
            "more_info": issue["more_info"]
        })

        update_metrics(results, severity)
    
    return results

def parse_phpstan_results(results, scan_data, file_path):
    results["run_started"] = "N/A"  # PHPStan doesn't provide a timestamp
    
    for file_data in scan_data.get("files", []):
        for error in file_data.get("messages", []):
            severity = "MEDIUM"  # PHPStan doesn't provide severity, default to medium
            
            results["issues"].append({
                "test_id": "PHPSTAN_" + str(error.get("line", 0)),
                "test_name": error.get("message", "Unknown issue"),
                "severity": severity,
                "confidence": "HIGH",
                "cwe": "N/A",
                "cwe_link": "#",
                "location": file_path,
                "line": error.get("line", 0),
                "code": error.get("message", ""),
                "description": error.get("message", "No description"),
                "more_info": "https://phpstan.org/user-guide/rule-reference"
            })

            update_metrics(results, severity)
    
    return results

def parse_eslint_results(results, scan_data, file_path):
    results["run_started"] = "N/A"  # ESLint doesn't provide a timestamp
    
    for file_data in scan_data:
        for message in file_data.get("messages", []):
            severity = message.get("severity", 1)
            severity_map = {2: "HIGH", 1: "MEDIUM", 0: "LOW"}
            
            results["issues"].append({
                "test_id": message.get("ruleId", "ESLINT_RULE"),
                "test_name": message.get("message", "Unknown issue"),
                "severity": severity_map.get(severity, "LOW"),
                "confidence": "HIGH",
                "cwe": "N/A",
                "cwe_link": "#",
                "location": file_path,
                "line": message.get("line", 0),
                "code": message.get("source", ""),
                "description": message.get("message", "No description"),
                "more_info": f"https://eslint.org/docs/rules/{message.get('ruleId', '')}"
            })

            update_metrics(results, severity_map.get(severity, "LOW"))
    
    return results

def update_metrics(results, severity):
    results["metrics"]["total_issues"] += 1
    severity_lower = severity.lower()
    if severity_lower in results["metrics"]:
        results["metrics"][severity_lower] += 1
