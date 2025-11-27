import os
import sys

# Suspicious keywords to look for
SUSPICIOUS_STRINGS = [
    "powershell", "cmd.exe", "wscript", "cscript", "regsvr32",
    "rundll32", "bitsadmin", "curl", "Invoke-Expression", "Start-Process",
    "Base64", "AutoOpen", "Document_Open", "Sub AutoOpen", "Sub Document_Open"
]

def check_file(path):
    results = {}
    score = 0

    # Check file extension
    ext = os.path.splitext(path)[1].lower()
    if ext in [".exe", ".dll", ".bin"]:
        results["ExecutableDetected"] = "Yes"
        score += 30
    else:
        results["ExecutableDetected"] = "No"

    if ext in [".js", ".vbs", ".bat", ".cmd", ".ps1", ".sh", ".py"]:
        results["ScriptFile"] = "Yes"
        score += 20
    else:
        results["ScriptFile"] = "No"

    if ext in [".doc", ".xls", ".ppt"]:
        results["MacroMarkers"] = "Yes"
        score += 25
    else:
        results["MacroMarkers"] = "No"

    # Read file content (safe limit)
    try:
        with open(path, "rb") as f:
            data = f.read(200000)  # read first 200KB
            text = data.decode(errors="ignore").lower()
    except Exception:
        text = ""

    # Check suspicious strings
    hits = [s for s in SUSPICIOUS_STRINGS if s.lower() in text]
    if hits:
        results["SuspiciousStrings"] = "Yes"
        score += 25
    else:
        results["SuspiciousStrings"] = "No"

    # Calculate percentages
    risk_percent = min(100, score)
    safe_percent = 100 - risk_percent
    status = "Safe" if risk_percent <= 20 else ("NeedsReview" if risk_percent <= 50 else "HighRisk")

    results["Result"] = f"{status} | Safe {safe_percent}% / Suspicious {risk_percent}%"
    return results

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python virus_checker.py <file_path>")
        sys.exit(1)

    file_path = sys.argv[1]
    if not os.path.isfile(file_path):
        print("Error: File not found.")
        sys.exit(1)

    results = check_file(file_path)
    for k, v in results.items():
        print(f"{k}: {v}")
