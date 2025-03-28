import json
import subprocess
import os

def scan_code(file_path):
    results = {
        "filename": os.path.basename(file_path),
        "language": "Python",
        "issues": [],
        "metrics": {
            "total_issues": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "lines_of_code": 0
        },
        "checklists": {}
    }

    try:
        output = subprocess.run(
            ["bandit", "-r", file_path, "-f", "json", "--confidence"],
            capture_output=True,
            text=True,
            timeout=30
        )

        if output.returncode not in [0, 1]:
            results["error"] = f"Bandit scan failed: {output.stderr}"
            return results

        scan_data = json.loads(output.stdout)
        
        # Add metrics
        results["metrics"]["lines_of_code"] = scan_data.get("metrics", {}).get("loc", 0)
        
        for issue in scan_data.get("results", []):
            severity = issue["issue_severity"].lower()
            test_id = issue["test_id"]
            
            # Update metrics
            results["metrics"][severity] += 1
            results["metrics"]["total_issues"] += 1
            
            # Build checklist category
            if test_id not in results["checklists"]:
                results["checklists"][test_id] = {
                    "title": issue["test_name"],
                    "issues": []
                }
            
            # Add detailed issue
            results["checklists"][test_id]["issues"].append({
                "severity": issue["issue_severity"].upper(),
                "confidence": issue["issue_confidence"].capitalize(),
                "cwe": issue.get("issue_cwe", {}).get("id", "N/A"),
                "cwe_link": issue.get("issue_cwe", {}).get("link", "#"),
                "location": issue["filename"],
                "line": issue["line_number"],
                "code": issue["code"],
                "description": issue["issue_text"],
                "more_info": issue["more_info"]
            })

    except subprocess.TimeoutExpired:
        results["error"] = "Scan timed out after 30 seconds"
    except Exception as e:
        results["error"] = f"Unexpected error: {str(e)}"
    
    return results
