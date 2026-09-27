#!/usr/bin/env python3
"""Verify public HTTPS over enp5s0, without proxies or system Fake-IP DNS.

For a disconnect control, pass the previously written report to --reuse-addresses.
No system DNS, routes, proxy settings, or interface configuration are modified.
"""

import argparse
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import subprocess

TARGETS = {"www.baidu.com": "/", "dns.alidns.com": "/resolve?name=www.baidu.com&type=A"}
BASE = ["curl", "--silent", "--show-error", "--fail", "--noproxy", "*",
        "--interface", "if!enp5s0", "--ipv4", "--connect-timeout", "5", "--max-time", "8"]


def resolve(host):
    proc = subprocess.run(
        [*BASE, "--resolve", "dns.alidns.com:443:223.5.5.5",
         f"https://dns.alidns.com/resolve?name={host}&type=A"],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError("bound HTTPS DNS request failed")
    data = json.loads(proc.stdout)
    for answer in data.get("Answer", []):
        if answer.get("type") == 1:
            address = ipaddress.IPv4Address(answer["data"])
            if address.is_global:
                return str(address)
    raise RuntimeError("DNS response did not contain a public IPv4 address")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reuse-addresses", type=Path)
    args = parser.parse_args()
    addresses = json.loads(args.reuse_addresses.read_text())["addresses"] if args.reuse_addresses else {}
    checks = []
    for host in TARGETS:
        try:
            address = str(ipaddress.IPv4Address(addresses[host])) if host in addresses else resolve(host)
            if not ipaddress.IPv4Address(address).is_global:
                raise ValueError("non-public address")
        except (ValueError, KeyError, RuntimeError):
            checks.append({"host": host, "error": "public address resolution failed"})
            continue
        addresses[host] = address
        proc = subprocess.run(
            [*BASE, "--resolve", f"{host}:443:{address}", "--output", "/dev/null",
             "--write-out", "%{json}", f"https://{host}{TARGETS[host]}"], capture_output=True, text=True,
        )
        try:
            metrics = json.loads(proc.stdout)
        except ValueError:
            metrics = {}
        checks.append({"host": host, "returncode": proc.returncode,
                       **{key: metrics.get(key) for key in
                          ("http_code", "local_ip", "remote_ip", "ssl_verify_result", "time_total", "size_download")}})
    print(json.dumps({"time": datetime.now(timezone.utc).isoformat(), "interface": "enp5s0",
                      "proxy_disabled": True, "system_dns_bypassed": True,
                      "addresses": {host: addresses[host] for host in TARGETS if host in addresses},
                      "checks": checks}, indent=2))
    return 0 if len(checks) == len(TARGETS) and all(check.get("returncode") == 0 for check in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
