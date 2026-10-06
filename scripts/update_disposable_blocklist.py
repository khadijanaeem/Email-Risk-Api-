from pathlib import Path
import urllib.request

URL = "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf"
OUT = Path("backend/app/data/disposable_domains.txt")

def main():
    req = urllib.request.Request(URL, headers={"User-Agent": "email-risk-api-blocklist-updater/1.0"})
    with urllib.request.urlopen(req, timeout=30) as response:
        text = response.read().decode("utf-8")
    domains = set()
    for line in text.splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        line = line.lstrip("@*.")
        if "." in line and " " not in line:
            domains.add(line)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("# Auto-generated from the upstream disposable-email-domains project.\n" + "\n".join(sorted(domains)) + "\n", encoding="utf-8")
    print(f"Wrote {len(domains)} domains to {OUT}")

if __name__ == "__main__":
    main()
