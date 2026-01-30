import psutil
import os
from datetime import datetime

SUSPICIOUS_KEYWORDS = [
    "keylog", "hook", "stealer", "spy",
    "logger", "rat", "trojan", "grabber"
]

RISK_THRESHOLD = 4


def analyze_process(proc):
    risk = 0
    reasons = []

    name = proc.info['name'].lower() if proc.info['name'] else ""

    # 1. Keyword-based detection
    for word in SUSPICIOUS_KEYWORDS:
        if word in name:
            risk += 3
            reasons.append(f"Suspicious keyword in name: '{word}'")

    # 2. Missing executable path
    if not proc.info['exe']:
        risk += 1
        reasons.append("No executable path found")

    # 3. Active network connections
    try:
        connections = proc.connections(kind="inet")
        if connections:
            risk += 2
            reasons.append(f"Has {len(connections)} active network connection(s)")
    except Exception:
        pass

    return risk, reasons


def main():
    print("🛡 Suspicious Process + Network Monitor (Purple Team Edition)\n")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_file = "scan_report.txt"

    with open(report_file, "w", encoding="utf-8") as f:
        f.write("Suspicious Process & Network Scan Report\n")
        f.write(f"Scan Time: {timestamp}\n")
        f.write("=" * 55 + "\n\n")

        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                risk, reasons = analyze_process(proc)

                if risk >= RISK_THRESHOLD:
                    status = "⚠ SUSPICIOUS"
                    line = f"{status} | PID {proc.pid} | {proc.info['name']} | Score: {risk}/10\n"
                    print(line.strip())
                    f.write(line)

                    for r in reasons:
                        detail = f"   - {r}\n"
                        print(detail.strip())
                        f.write(detail)

                    f.write("\n")

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    print("\n✔ Scan complete.")
    print(f"📄 Report saved to: {os.path.abspath(report_file)}")


if __name__ == "__main__":
    main()
    