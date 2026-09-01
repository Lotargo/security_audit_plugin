#!/usr/bin/env python3
import sys
import subprocess
import json

def check_dns(domain):
    results = {"domain": domain, "spf": None, "dmarc": None}
    try:
        # Check SPF / TXT
        txt_out = subprocess.check_output(["nslookup", "-type=TXT", domain], text=True, errors='ignore')
        for line in txt_out.splitlines():
            if "v=spf1" in line:
                results["spf"] = line.strip()

        # Check DMARC
        dmarc_out = subprocess.check_output(["nslookup", "-type=TXT", f"_dmarc.{domain}"], text=True, errors='ignore')
        for line in dmarc_out.splitlines():
            if "v=DMARC1" in line:
                results["dmarc"] = line.strip()
    except Exception as e:
        results["error"] = str(e)
    return results

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(json.dumps(check_dns(target), indent=2))
