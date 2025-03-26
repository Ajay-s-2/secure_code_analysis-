import logging

def scan_file(filepath, scan_type):
    logging.info(f"Scanning file: {filepath} as {scan_type}")

    vulnerabilities = []

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    for i, line in enumerate(lines, start=1):
        if scan_type == "python":
            if "eval(" in line:
                vulnerabilities.append(f"Line {i}: Possible code injection using eval()")
            if "subprocess.call" in line or "subprocess.Popen" in line:
                vulnerabilities.append(f"Line {i}: Possible command injection using subprocess")

        elif scan_type == "javascript":
            if "eval(" in line or "document.write(" in line:
                vulnerabilities.append(f"Line {i}: Possible XSS vulnerability")
            if "innerHTML" in line:
                vulnerabilities.append(f"Line {i}: DOM-based XSS risk")

        elif scan_type == "php":
            if "eval(" in line or "exec(" in line:
                vulnerabilities.append(f"Line {i}: Possible Remote Code Execution vulnerability")
            if "mysql_query(" in line:
                vulnerabilities.append(f"Line {i}: Possible SQL Injection risk")

    logging.info(f"Scan Completed: {len(vulnerabilities)} issues found")

    return vulnerabilities if vulnerabilities else ["No vulnerabilities found!"]
