#!/usr/bin/env python3
import subprocess
import os
import base64
import sys
import shlex
import signal
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import argparse
import shutil
import socket


def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully."""
    print(f"\n\n\033[33m[!]\033[0m Interrupted by user. Exiting...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

EXEC_TIMEOUT = 20
RDP_TIMEOUT = 45
MAX_THREADS = 10

VERBOSE = False
OUTPUT = False
RUN_ALL = True
SKIP_PORTSCAN = False
TOOLS_SPECIFIED = False
LINUX_MODE = False
DRY_RUN = False
MASK_CREDS = False
DOMAIN = None
EXEC_MODE = False
CUSTOM_PORTS = {}

VALID_TOOLS = [
    # Exec tools
    "winrm", "smbexec", "wmi", "ssh", "mssql", "psexec", "atexec", "rdp",
    # Auth-only tools
    "ldap", "ftp", "vnc", "kerberos", "postgresql", "mysql", "smtp", "imap", "redis", "ipmi"
]
NXC_TOOLS = {"smbexec", "wmi", "ssh", "rdp", "ldap", "ftp", "vnc"}
AUTH_ONLY_TOOLS = {"ldap", "ldaps", "ftp", "vnc", "kerberos", "postgresql", "mysql", "smtp", "imap", "redis", "ipmi"}

IMPACKET_PREFIX = "impacket-"  # or "" for .py suffix
NXC_CMD = "nxc"
WINRM_CMD = "evil-winrm"

print_lock = threading.Lock()
results_lock = threading.Lock()
RESULTS = []  # Collect (ip, user, cred, tool, status) tuples for summary

# ANSI color codes
class C:
    RESET = "\033[0m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    # Pale colors for section headers
    PEACH = "\033[38;5;216m"      # Soft peach/salmon for main sections
    PALE_BLUE = "\033[38;5;110m"  # Soft blue for user sections

def print_section(title, color=None):
    """Print a boxed section header."""
    if color is None:
        color = C.PEACH
    width = 60
    with print_lock:
        print()
        print(f"{color} {'=' * width}{C.RESET}")
        print(f"{color}|{C.RESET}    {title.ljust(width - 5)}{color}|{C.RESET}")
        print(f"{color} {'=' * width}{C.RESET}")

def print_target_header(ip):
    """Print target header in peach."""
    width = 60
    with print_lock:
        print()
        print(f"{C.PEACH} {'=' * width}{C.RESET}")
        print(f"{C.PEACH}|{C.RESET}    Target: {ip.ljust(width - 13)}{C.PEACH}|{C.RESET}")
        print(f"{C.PEACH} {'=' * width}{C.RESET}")

def print_user_header(user):
    """Print user sub-header in pale blue."""
    width = 56
    with print_lock:
        print()
        print(f"  {C.PALE_BLUE} {'=' * width}{C.RESET}")
        print(f"  {C.PALE_BLUE}|{C.RESET}    User: {user.ljust(width - 11)}{C.PALE_BLUE}|{C.RESET}")
        print(f"  {C.PALE_BLUE} {'=' * width}{C.RESET}")

def print_success(msg, indent=0):
    """Print success message in green."""
    prefix = "    " * indent
    with print_lock:
        print(f"{prefix}{C.GREEN}[+]{C.RESET} {msg}")

def print_error(msg, indent=0):
    """Print error message in red."""
    prefix = "    " * indent
    with print_lock:
        print(f"{prefix}{C.RED}[-]{C.RESET} {msg}")

def print_warning(msg, indent=0):
    """Print warning message in yellow."""
    prefix = "    " * indent
    with print_lock:
        print(f"{prefix}{C.YELLOW}[!]{C.RESET} {msg}")

def print_info(msg, indent=0):
    """Print info message in cyan."""
    prefix = "    " * indent
    with print_lock:
        print(f"{prefix}{C.CYAN}[*]{C.RESET} {msg}")

def print_verbose(msg, indent=0):
    """Print verbose message in magenta (only if VERBOSE enabled)."""
    if VERBOSE:
        prefix = "    " * indent
        with print_lock:
            print(f"{prefix}{C.MAGENTA}[v]{C.RESET} {msg}")

def print_output(msg):
    """Print command output (only if OUTPUT enabled and not VERBOSE)."""
    if OUTPUT and not VERBOSE:
        with print_lock:
            print(msg)

def print_table_header():
    """Print the tool results table header."""
    with print_lock:
        print(f"  {'Credential':<24} {'Service':<12} {'Auth':<8} {'Exec':<10} {'Notes'}")
        print(f"  {'─' * 24} {'─' * 12} {'─' * 8} {'─' * 10} {'─' * 20}")

def format_credential(cred):
    """Format credential for display, optionally masking it."""
    if not cred:
        return ""
    if not MASK_CREDS:
        return cred
    # For hashes, show first 8 chars
    if cred.startswith(':') or (len(cred) == 32 and all(c in '0123456789abcdefABCDEF' for c in cred)):
        return cred[:8] + "..."
    # For passwords, show first 4 chars
    if len(cred) <= 4:
        return cred
    return cred[:4] + "***"

def print_tool_result(tool, status, cred=None, message=None):
    """Print a table row for tool result."""
    credential = format_credential(cred).ljust(24)
    tool_padded = tool.ljust(12)
    with print_lock:
        if status == "success":
            print(f"  {credential} {tool_padded} {C.GREEN}{'OK':<8}{C.RESET} {C.GREEN}{'OK':<10}{C.RESET}")
        elif status == "auth":
            # Auth-only tools - show N/A for exec
            print(f"  {credential} {tool_padded} {C.GREEN}{'OK':<8}{C.RESET} {C.BLUE}{'N/A':<10}{C.RESET}")
        elif status == "error":
            note = message if message else ""
            print(f"  {credential} {tool_padded} {C.RED}{'FAILED':<8}{C.RESET} {C.RED}{'-':<10}{C.RESET} {note}")
        elif status == "warning":
            note = message.replace("AUTH OK, ", "").replace("AUTH OK ", "") if message else ""
            print(f"  {credential} {tool_padded} {C.GREEN}{'OK':<8}{C.RESET} {C.RED}{'FAILED':<10}{C.RESET} {note}")
        elif status == "skip":
            note = message if message else ""
            print(f"  {credential} {tool_padded} {C.BLUE}{'-':<8}{C.RESET} {C.BLUE}{'-':<10}{C.RESET} {note}")


def record_result(ip, user, cred, tool, auth_ok, exec_ok):
    """Record a result for the summary."""
    with results_lock:
        RESULTS.append((ip, user, cred, tool, auth_ok, exec_ok))


def print_summary():
    """Print summary of all successful authentications."""
    # Filter to only auth successes
    successes = [(ip, user, cred, tool, auth_ok, exec_ok)
                 for ip, user, cred, tool, auth_ok, exec_ok in RESULTS if auth_ok]

    if not successes:
        print_warning("No successful authentications found.")
        return

    print(f"\n{'Target':<16} {'Username':<16} {'Password':<20} {'Service':<12} {'Result'}")
    print(f"{'─' * 16} {'─' * 16} {'─' * 20} {'─' * 12} {'─' * 12}")

    for ip, user, cred, tool, auth_ok, exec_ok in successes:
        user_display = user[:15] if len(user) > 15 else user
        cred_display = cred[:19] if len(cred) > 19 else cred
        if exec_ok is True:
            result = f"{C.GREEN}Auth+Exec{C.RESET}"
        elif exec_ok is None:
            result = f"{C.CYAN}Auth{C.RESET}"  # Auth-only tool
        else:
            result = f"{C.YELLOW}Auth Only{C.RESET}"  # Auth OK but exec failed
        print(f"{ip:<16} {user_display:<16} {cred_display:<20} {tool:<12} {result}")


def parse_ip_range(ip_range):
    parts = ip_range.split('.')
    if len(parts) != 4:
        raise SystemExit("Invalid IP range format")

    def expand(part):
        vals = []
        for section in part.split(','):
            if '-' in section:
                s, e = map(int, section.split('-'))
                vals.extend(range(s, e + 1))
            else:
                vals.append(int(section))
        return vals

    expanded = [expand(p) for p in parts]
    return [f"{a}.{b}.{c}.{d}"
            for a in expanded[0]
            for b in expanded[1]
            for c in expanded[2]
            for d in expanded[3]]

def is_nthash(credential):
    cred = credential.lstrip(':').replace("'", "")
    if len(cred) == 32:
        try:
            int(cred, 16)
            return True
        except ValueError:
            return False
    return False


def load_credential_file(path):
    """
    Load credentials from file with colon-separated format:
    user1:password1
    user2:password2
    ...

    Blank lines and lines starting with # are ignored.
    Only the first colon is used as delimiter (passwords may contain colons).
    For hashes, use the hash directly as the password.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = [line.rstrip("\n\r") for line in f]
    except Exception as e:
        print_error(f"Cannot read credential file '{path}': {e}")
        sys.exit(1)
    creds = []

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if ':' not in line:
            raise SystemExit(f"Credential file line {line_num}: missing colon delimiter. Expected format: username:password")

        user, cred = line.split(':', 1)
        creds.append((user.strip(), cred))

    return creds


def load_values_from_file(path):
    """
    Load values from a file (one per line).
    Blank lines and lines starting with # are ignored.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = [line.rstrip("\n\r") for line in f]
    except Exception as e:
        print_error(f"Cannot read file '{path}': {e}")
        sys.exit(1)

    values = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            values.append(stripped)

    return values


def resolve_argument(value):
    """
    If value is a path to an existing file, load values from it.
    Otherwise return the value as a single-item list.
    """
    if os.path.isfile(value):
        return load_values_from_file(value)
    return [value]

def normalize_tool_name(name):
    """Normalize tool name aliases to canonical form."""
    name = name.lower().strip()
    aliases = {
        "evilwinrm": "winrm",
        "evil-winrm": "winrm",
        "postgres": "postgresql",
        "psql": "postgresql",
        "kerb": "kerberos",
        "krb": "kerberos",
        "krb5": "kerberos",
        "imaps": "imap",
        "smtps": "smtp",
    }
    return aliases.get(name, name)


def parse_tools_list(tools_str):
    """Parse comma-separated list of tools, validating each one."""
    tools = []
    for t in tools_str.split(','):
        normalized = normalize_tool_name(t)
        if normalized not in VALID_TOOLS:
            print_error(f"Invalid tool '{t}'. Valid options: {', '.join(VALID_TOOLS)}")
            sys.exit(1)
        if normalized not in tools:
            tools.append(normalized)
    return tools

def check_port(ip, port, timeout=1):
    """Check if a port is open on the given IP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False

def get_port(tool):
    """Get port for a tool, checking custom ports first."""
    DEFAULT_PORTS = {
        "psexec": 445, "smbexec": 445, "atexec": 445, "wmi": 135,
        "rdp": 3389, "mssql": 1433, "ssh": 22, "winrm": 5985, "winrm-ssl": 5986,
        "ldap": 389, "ldaps": 636, "ftp": 21, "vnc": 5900,
        "kerberos": 88, "postgresql": 5432, "mysql": 3306,
        "smtp": 587, "imap": 993, "redis": 6379, "ipmi": 623
    }
    # Map variant names to their base for custom port lookup
    base_tool = {"winrm-ssl": "winrm", "ldaps": "ldap", "psexec": "smb", "smbexec": "smb", "atexec": "smb"}.get(tool, tool)
    return CUSTOM_PORTS.get(base_tool, DEFAULT_PORTS.get(tool))


def scan_ports_for_tools(ip, tool_list):
    """
    Scan ports for given tools and return viable tools.
    For winrm, checks port 5985 for winrm and 5986 for winrm-ssl (unless custom port set).
    For ldap, checks port 389 for ldap and 636 for ldaps (unless custom port set).
    Returns tuple of (viable_tools, open_ports)
    """
    viable_tools = []
    open_ports = []

    tools_to_check = tool_list if tool_list else VALID_TOOLS

    for tool in tools_to_check:
        # Check both winrm ports (unless custom port specified)
        if tool == "winrm":
            if "winrm" in CUSTOM_PORTS:
                port = CUSTOM_PORTS["winrm"]
                if check_port(ip, port):
                    viable_tools.append("winrm")
                    if port not in open_ports:
                        open_ports.append(port)
            else:
                if check_port(ip, 5985):
                    viable_tools.append("winrm")
                    if 5985 not in open_ports:
                        open_ports.append(5985)
                if check_port(ip, 5986):
                    viable_tools.append("winrm-ssl")
                    if 5986 not in open_ports:
                        open_ports.append(5986)
        # Check both ldap ports (unless custom port specified)
        elif tool == "ldap":
            if "ldap" in CUSTOM_PORTS:
                port = CUSTOM_PORTS["ldap"]
                if check_port(ip, port):
                    viable_tools.append("ldap")
                    if port not in open_ports:
                        open_ports.append(port)
            else:
                if check_port(ip, 389):
                    viable_tools.append("ldap")
                    if 389 not in open_ports:
                        open_ports.append(389)
                if check_port(ip, 636):
                    viable_tools.append("ldaps")
                    if 636 not in open_ports:
                        open_ports.append(636)
        else:
            port = get_port(tool)
            if port and check_port(ip, port):
                viable_tools.append(tool)
                if port not in open_ports:
                    open_ports.append(port)

    return viable_tools, open_ports

def build_cmd(tool, user, target, credential, command):
    """Build command for authentication check or execution."""
    use_hash = is_nthash(credential)
    hash_val = credential.lstrip(':').replace("'", "")
    quoted_user = shlex.quote(user)
    quoted_cred = shlex.quote(credential)

    # Get custom port if set
    port = get_port(tool)
    port_flag = f" --port {port}" if port and port != get_port(tool) else ""

    # For nxc tools, add --no-output unless -o was passed (only in exec mode)
    nxc_output_flag = "" if OUTPUT else " --no-output"

    # Helper for nxc port flag
    def nxc_port(tool_name):
        base = {"winrm-ssl": "winrm", "ldaps": "ldap", "psexec": "smb", "smbexec": "smb", "atexec": "smb"}.get(tool_name, tool_name)
        if base in CUSTOM_PORTS:
            return f" --port {CUSTOM_PORTS[base]}"
        return ""

    # === AUTH-ONLY MODE (default) ===
    if not EXEC_MODE:
        # SMB-based tools (psexec, smbexec, atexec) -> nxc smb for auth
        if tool in ("psexec", "smbexec", "atexec"):
            p = nxc_port("smb")
            return (f"{NXC_CMD} smb {target} -u {quoted_user} -H {hash_val}{p}"
                    if use_hash else
                    f"{NXC_CMD} smb {target} -u {quoted_user} -p {quoted_cred}{p}")

        if tool == "wmi":
            p = nxc_port("wmi")
            return (f"{NXC_CMD} wmi {target} -u {quoted_user} -H {hash_val}{p}"
                    if use_hash else
                    f"{NXC_CMD} wmi {target} -u {quoted_user} -p {quoted_cred}{p}")

        if tool in ("winrm", "winrm-ssl"):
            p = nxc_port("winrm")
            ssl = " --ssl" if tool == "winrm-ssl" else ""
            return (f"{NXC_CMD} winrm {target} -u {quoted_user} -H {hash_val}{p}{ssl}"
                    if use_hash else
                    f"{NXC_CMD} winrm {target} -u {quoted_user} -p {quoted_cred}{p}{ssl}")

        if tool == "ssh":
            p = nxc_port("ssh")
            return f"{NXC_CMD} ssh {target} -u {quoted_user} -p {quoted_cred}{p}"

        if tool == "rdp":
            p = nxc_port("rdp")
            return (f"{NXC_CMD} rdp {target} -u {quoted_user} -H {hash_val}{p}"
                    if use_hash else
                    f"{NXC_CMD} rdp {target} -u {quoted_user} -p {quoted_cred}{p}")

        if tool == "mssql":
            p = nxc_port("mssql")
            return (f"{NXC_CMD} mssql {target} -u {quoted_user} -H {hash_val}{p}"
                    if use_hash else
                    f"{NXC_CMD} mssql {target} -u {quoted_user} -p {quoted_cred}{p}")

    # === EXEC MODE ===
    else:
        b64 = base64.b64encode(command.encode("utf-16le")).decode()
        impacket_auth = shlex.quote(f"{user}:{credential}@{target}")
        impacket_auth_hash = f"{quoted_user}@{target}"

        if tool == "psexec":
            cmd = impacket_cmd("psexec")
            return (f"{cmd} -hashes :{hash_val} {impacket_auth_hash} 'powershell -enc {b64}'"
                    if use_hash else
                    f"{cmd} {impacket_auth} 'powershell -enc {b64}'")

        if tool == "mssql":
            cmd = impacket_cmd("mssqlclient")
            return (f"{cmd} -hashes :{hash_val} {impacket_auth_hash} -windows-auth -command 'enable_xp_cmdshell' -command 'xp_cmdshell powershell -enc {b64}'"
                    if use_hash else
                    f"{cmd} {impacket_auth} -windows-auth -command 'enable_xp_cmdshell' -command 'xp_cmdshell powershell -enc {b64}'")

        if tool == "atexec":
            cmd = impacket_cmd("atexec")
            return (f"{cmd} -hashes :{hash_val} {impacket_auth_hash} 'powershell -enc {b64}'"
                    if use_hash else
                    f"{cmd} {impacket_auth} 'powershell -enc {b64}'")

        if tool == "winrm":
            return (f"echo 'powershell -enc {b64}' | {WINRM_CMD} -i {target} -u {quoted_user} -H {hash_val}"
                    if use_hash else
                    f"echo 'powershell -enc {b64}' | {WINRM_CMD} -i {target} -u {quoted_user} -p {quoted_cred}")

        if tool == "winrm-ssl":
            return (f"echo 'powershell -enc {b64}' | {WINRM_CMD} -i {target} -u {quoted_user} -H {hash_val} --ssl"
                    if use_hash else
                    f"echo 'powershell -enc {b64}' | {WINRM_CMD} -i {target} -u {quoted_user} -p {quoted_cred} --ssl")

        if tool == "smbexec":
            p = nxc_port("smb")
            return (f"{NXC_CMD} smb {target} -H {hash_val} -u {quoted_user} -X 'powershell -enc {b64}' --exec-method smbexec{p}{nxc_output_flag}"
                    if use_hash else
                    f"{NXC_CMD} smb {target} -p {quoted_cred} -u {quoted_user} -X 'powershell -enc {b64}' --exec-method smbexec{p}{nxc_output_flag}")

        if tool == "wmi":
            p = nxc_port("wmi")
            return (f"{NXC_CMD} wmi {target} -H {hash_val} -u {quoted_user} -X 'cmd /c \"powershell -enc {b64}\"'{p}"
                    if use_hash else
                    f"{NXC_CMD} wmi {target} -p {quoted_cred} -u {quoted_user} -X 'cmd /c \"powershell -enc {b64}\"'{p}")

        if tool == "ssh":
            p = nxc_port("ssh")
            if LINUX_MODE:
                b64 = base64.b64encode(command.encode("utf-8")).decode()
                return f"{NXC_CMD} ssh {target} -p {quoted_cred} -u {quoted_user} -x 'echo {b64} | base64 -d | $0'{p}{nxc_output_flag}"
            return f"{NXC_CMD} ssh {target} -p {quoted_cred} -u {quoted_user} -x 'powershell -enc {b64}'{p}{nxc_output_flag}"

        if tool == "rdp":
            p = nxc_port("rdp")
            return (f"{NXC_CMD} rdp {target} -u {quoted_user} -H {hash_val} -X 'powershell -enc {b64}'{p}{nxc_output_flag}"
                    if use_hash else
                    f"{NXC_CMD} rdp {target} -u {quoted_user} -p {quoted_cred} -X 'powershell -enc {b64}'{p}{nxc_output_flag}")

    # === AUTH-ONLY TOOLS (same in both modes) ===
    if tool == "ldap":
        p = nxc_port("ldap")
        return (f"{NXC_CMD} ldap {target} -u {quoted_user} -H {hash_val}{p}"
                if use_hash else
                f"{NXC_CMD} ldap {target} -u {quoted_user} -p {quoted_cred}{p}")

    if tool == "ldaps":
        p = nxc_port("ldap")
        return (f"{NXC_CMD} ldap {target} -u {quoted_user} -H {hash_val}{p} --ssl"
                if use_hash else
                f"{NXC_CMD} ldap {target} -u {quoted_user} -p {quoted_cred}{p} --ssl")

    if tool == "ftp":
        p = nxc_port("ftp")
        return f"{NXC_CMD} ftp {target} -u {quoted_user} -p {quoted_cred}{p}"

    if tool == "vnc":
        p = nxc_port("vnc")
        return f"{NXC_CMD} vnc {target} -p {quoted_cred}{p}"

    if tool == "kerberos":
        if not DOMAIN:
            return None
        cmd = impacket_cmd("getTGT")
        return (f"{cmd} -hashes :{hash_val} {DOMAIN}/{user} -dc-ip {target}"
                if use_hash else
                f"{cmd} {DOMAIN}/{user}:{credential} -dc-ip {target}")

    if tool == "postgresql":
        p = CUSTOM_PORTS.get("postgresql", 5432)
        return f"PGPASSWORD={quoted_cred} psql -h {target} -p {p} -U {user} -d postgres -c 'SELECT 1' -w 2>&1"

    if tool == "mysql":
        p = CUSTOM_PORTS.get("mysql", 3306)
        return f"mysql -h {target} -P {p} -u {user} -p{credential} -e 'SELECT 1' 2>&1"

    if tool == "smtp":
        p = CUSTOM_PORTS.get("smtp", 587)
        py = f"import smtplib;s=smtplib.SMTP('{target}',{p},timeout=10);s.starttls();s.login('{user}','{credential}');print('OK')"
        return f"python3 -c {shlex.quote(py)} 2>&1"

    if tool == "imap":
        p = CUSTOM_PORTS.get("imap", 993)
        py = f"import imaplib;m=imaplib.IMAP4_SSL('{target}',{p});m.login('{user}','{credential}');print('OK')"
        return f"python3 -c {shlex.quote(py)} 2>&1"

    if tool == "redis":
        p = CUSTOM_PORTS.get("redis", 6379)
        if credential:
            return f"redis-cli -h {target} -p {p} -a {quoted_cred} PING 2>&1"
        return f"redis-cli -h {target} -p {p} PING 2>&1"

    if tool == "ipmi":
        return f"ipmitool -I lanplus -H {target} -U {user} -P {quoted_cred} chassis status 2>&1"

    raise Exception(f"Unknown tool: {tool}")

def run_chain(user, ip, credential, command, tool_list=None):
    """Returns (success_tool, out, cmd, auth_successes) or (None, None, None, auth_successes)"""
    chain = tool_list if tool_list else VALID_TOOLS
    auth_successes = []  # Track tools where auth succeeded but exec failed

    # test both winrm and ldap variants when specified
    if TOOLS_SPECIFIED:
        expanded_chain = []
        for tool in chain:
            if tool == "winrm":
                expanded_chain.extend(["winrm", "winrm-ssl"])
            elif tool == "ldap":
                expanded_chain.extend(["ldap", "ldaps"])
            elif tool not in expanded_chain:  # Avoid duplicates
                expanded_chain.append(tool)
        chain = expanded_chain

    for tool in chain:
        # Can't pass the hash with SSH
        if tool == "ssh" and is_nthash(credential):
            print_tool_result(tool, "skip", credential, "cannot pass the hash")
            continue

        if tool == "rdp" and NXC_CMD == "crackmapexec":
            print_tool_result(tool, "skip", credential, "crackmapexec doesn't support RDP exec")
            continue

        # Kerberos requires --domain
        if tool == "kerberos" and not DOMAIN:
            print_tool_result(tool, "skip", credential, "requires --domain")
            continue

        # VNC is password-only
        if tool == "vnc" and is_nthash(credential):
            print_tool_result(tool, "skip", credential, "VNC is password-only")
            continue

        # FTP doesn't support hashes
        if tool == "ftp" and is_nthash(credential):
            print_tool_result(tool, "skip", credential, "cannot pass the hash")
            continue

        # Database tools don't support hashes
        if tool in ("postgresql", "mysql") and is_nthash(credential):
            print_tool_result(tool, "skip", credential, "cannot pass the hash")
            continue

        # Mail/redis/ipmi don't support hashes
        if tool in ("smtp", "imap", "redis", "ipmi") and is_nthash(credential):
            print_tool_result(tool, "skip", credential, "cannot pass the hash")
            continue

        if tool == "mssql":
            print_verbose(f"Attempting to enable xp_cmdshell on {ip}...")

        cmd = build_cmd(tool, user, ip, credential, command)

        # Dry-run mode: just show the command, don't execute
        if DRY_RUN:
            with print_lock:
                print(f"    {C.CYAN}{tool}{C.RESET}")
                print(f"      {C.YELLOW}${C.RESET} {cmd}")
                print()
            continue

        print_verbose(f"Command: {cmd}")

        try:
            timeout = RDP_TIMEOUT if tool == "rdp" else EXEC_TIMEOUT
            result = subprocess.run(cmd, shell=True, timeout=timeout, capture_output=True)
            rc = result.returncode
            out = result.stdout.decode("utf-8", errors="ignore")
            print_verbose(f"Output (rc={rc}): {out if out else '(empty)'}")

        except subprocess.TimeoutExpired:
            print_tool_result(tool, "error", credential, "timed out")
            continue

        # === AUTH-ONLY MODE: All exec-capable tools use nxc for auth check ===
        if not EXEC_MODE and tool in ("psexec", "smbexec", "atexec", "wmi", "winrm", "winrm-ssl", "ssh", "rdp", "mssql"):
            # Check for Guest login (not a real authentication)
            if '(Guest)' in out:
                print_tool_result(tool, "error", credential, "Guest login (invalid creds)")
                continue
            if '[+]' in out and '[-]' not in out:
                record_result(ip, user, credential, tool, True, None)
                print_tool_result(tool, "auth", credential)
                if not RUN_ALL:
                    return (tool, out, cmd, auth_successes)
                continue
            print_tool_result(tool, "error", credential)
            continue

        # Auth-only nxc tools (ldap, ldaps, ftp, vnc)
        if tool in ("ldap", "ldaps", "ftp", "vnc"):
            # Check for Guest login (not a real authentication)
            if '(Guest)' in out:
                print_tool_result(tool, "error", credential, "Guest login (invalid creds)")
                continue
            if '[+]' in out and '[-]' not in out:
                record_result(ip, user, credential, tool, True, None)
                print_tool_result(tool, "auth", credential)
                if not RUN_ALL:
                    return (tool, out, cmd, auth_successes)
                continue
            print_tool_result(tool, "error", credential)
            continue

        # Kerberos auth check
        if tool == "kerberos":
            if "Saving ticket" in out or "[*] Saving ticket" in out:
                record_result(ip, user, credential, tool, True, None)
                print_tool_result(tool, "auth", credential)
                if not RUN_ALL:
                    return (tool, out, cmd, auth_successes)
                continue
            msg = None
            if "KDC_ERR_PREAUTH_FAILED" in out:
                msg = "Bad password"
            elif "KDC_ERR_C_PRINCIPAL_UNKNOWN" in out:
                msg = "User not found"
            print_tool_result(tool, "error", credential, msg)
            continue

        # PostgreSQL auth check
        if tool == "postgresql":
            if rc == 0 and ("1 row" in out or "(1 row)" in out or "1" in out):
                record_result(ip, user, credential, tool, True, None)
                print_tool_result(tool, "auth", credential)
                if not RUN_ALL:
                    return (tool, out, cmd, auth_successes)
                continue
            print_tool_result(tool, "error", credential)
            continue

        # MySQL auth check
        if tool == "mysql":
            if rc == 0 and "ERROR" not in out:
                record_result(ip, user, credential, tool, True, None)
                print_tool_result(tool, "auth", credential)
                if not RUN_ALL:
                    return (tool, out, cmd, auth_successes)
                continue
            print_tool_result(tool, "error", credential)
            continue

        # SMTP/IMAP auth check
        if tool in ("smtp", "imap"):
            if "OK" in out and "Error" not in out and "error" not in out:
                record_result(ip, user, credential, tool, True, None)
                print_tool_result(tool, "auth", credential)
                if not RUN_ALL:
                    return (tool, out, cmd, auth_successes)
                continue
            print_tool_result(tool, "error", credential)
            continue

        # Redis auth check
        if tool == "redis":
            if "PONG" in out:
                record_result(ip, user, credential, tool, True, None)
                print_tool_result(tool, "auth", credential)
                if not RUN_ALL:
                    return (tool, out, cmd, auth_successes)
                continue
            print_tool_result(tool, "error", credential)
            continue

        # IPMI auth check
        if tool == "ipmi":
            if rc == 0 and ("System Power" in out or "Chassis Power" in out):
                record_result(ip, user, credential, tool, True, None)
                print_tool_result(tool, "auth", credential)
                if not RUN_ALL:
                    return (tool, out, cmd, auth_successes)
                continue
            print_tool_result(tool, "error", credential)
            continue

        # psexec can have "[-]" in stdout if some shares are writeable and others aren't
        if tool == "psexec":
            if "Found writable share" in out:
                if "Stopping service" in out:
                    record_result(ip, user, credential, tool, True, True)
                    if RUN_ALL:
                        print_tool_result(tool, "success", credential)
                        print_output(out)
                        continue
                    return (tool, out, cmd)
                else:
                    record_result(ip, user, credential, tool, True, False)
                    print_tool_result(tool, "warning", credential, "AUTH OK, but timed out (likely AV)")
                    auth_successes.append(tool)
                    continue
            elif "is not writable" in out or "Requesting shares" in out:
                # Auth succeeded but no writable shares found
                record_result(ip, user, credential, tool, True, False)
                print_tool_result(tool, "warning", credential, "AUTH OK, no writable shares")
                auth_successes.append(tool)
                continue
            else:
                print_tool_result(tool, "error", credential)
                continue

        if tool == "atexec":
            if "rpc_s_access_denied" in out:
                record_result(ip, user, credential, tool, True, False)
                print_tool_result(tool, "warning", credential, "AUTH OK, task creation denied")
                auth_successes.append(tool)
                continue
            elif "[-]" in out:
                print_tool_result(tool, "error", credential)
                continue

        if tool == "rdp":
            if "[-] Clipboard" in out:
                record_result(ip, user, credential, tool, True, False)
                print_tool_result(tool, "warning", credential, "AUTH OK, clipboard init failed")
                auth_successes.append(tool)
                continue
            elif "unrecognized arguments" in out:
                print_tool_result(tool, "error", credential, "NetExec outdated, reinstall for RDP support")
                continue
            elif "[-]" in out:
                print_tool_result(tool, "error", credential)
                continue
            # RDP with -X and --no-output returns empty on failure - do auth check
            elif rc != 0 or out == "":
                # Run auth-only check to see if RDP access exists
                auth_cmd = f"{NXC_CMD} rdp {ip} -u {shlex.quote(user)} -p {shlex.quote(credential)}"
                if is_nthash(credential):
                    hash_val = credential.lstrip(':').replace("'", "")
                    auth_cmd = f"{NXC_CMD} rdp {ip} -u {shlex.quote(user)} -H {hash_val}"
                print_verbose(f"RDP exec failed, checking auth: {auth_cmd}")
                try:
                    auth_result = subprocess.run(auth_cmd, shell=True, timeout=EXEC_TIMEOUT, capture_output=True)
                    auth_out = auth_result.stdout.decode("utf-8", errors="ignore")
                    print_verbose(f"Auth check output: {auth_out}")
                    # Check for Guest login (not a real authentication)
                    if "(Guest)" in auth_out:
                        print_tool_result(tool, "error", credential, "Guest login (invalid creds)")
                        continue
                    if "[+]" in auth_out and "[-]" not in auth_out:
                        record_result(ip, user, credential, tool, True, False)
                        print_tool_result(tool, "warning", credential, "AUTH OK, exec failed. Try manual RDP.")
                        auth_successes.append(tool)
                        continue
                except Exception:
                    pass
                print_tool_result(tool, "error", credential)
                continue

        if tool in NXC_TOOLS:
            # Check for Guest login (not a real authentication)
            if '(Guest)' in out:
                print_tool_result(tool, "error", credential, "Guest login (invalid creds)")
                continue
            if '[-]' in out:
                if "Could not retrieve" in out:
                    record_result(ip, user, credential, tool, True, False)
                    print_tool_result(tool, "warning", credential, "AUTH OK, command failed (try without -o)")
                    auth_successes.append(tool)
                else:
                    print_tool_result(tool, "error", credential)
                continue
            if tool == "ssh" and 'Linux - Shell' in out and not LINUX_MODE:
                record_result(ip, user, credential, tool, True, False)
                print_tool_result(tool, "warning", credential, "AUTH OK, Linux detected. Use --linux")
                auth_successes.append(tool)
                continue
            if '[+]' in out and '[+] Executed' not in out:
                # Double-check it's not a Guest login before marking as auth success
                if '(Guest)' not in out:
                    record_result(ip, user, credential, tool, True, False)
                    print_tool_result(tool, "warning", credential, "AUTH OK, command failed (check permissions)")
                    auth_successes.append(tool)
                else:
                    print_tool_result(tool, "error", credential, "Guest login (invalid creds)")
                continue
            # WMI with empty output - do auth check like RDP
            if tool == "wmi" and (rc != 0 or out == ""):
                auth_cmd = f"{NXC_CMD} smb {ip} -u {shlex.quote(user)} -p {shlex.quote(credential)}"
                if is_nthash(credential):
                    hash_val = credential.lstrip(':').replace("'", "")
                    auth_cmd = f"{NXC_CMD} smb {ip} -u {shlex.quote(user)} -H {hash_val}"
                print_verbose(f"WMI exec failed, checking SMB auth: {auth_cmd}")
                try:
                    auth_result = subprocess.run(auth_cmd, shell=True, timeout=EXEC_TIMEOUT, capture_output=True)
                    auth_out = auth_result.stdout.decode("utf-8", errors="ignore")
                    print_verbose(f"Auth check output: {auth_out}")
                    # Check for Guest login (not a real authentication)
                    if "(Guest)" in auth_out:
                        print_tool_result(tool, "error", credential, "Guest login (invalid creds)")
                        continue
                    if "[+]" in auth_out and "[-]" not in auth_out:
                        record_result(ip, user, credential, tool, True, False)
                        print_tool_result(tool, "warning", credential, "WMI exec failed")
                        auth_successes.append(tool)
                        continue
                except Exception:
                    pass
                print_tool_result(tool, "error", credential)
                continue
            # SSH with empty output - do auth check
            if tool == "ssh" and (rc != 0 or out == ""):
                auth_cmd = f"{NXC_CMD} ssh {ip} -u {shlex.quote(user)} -p {shlex.quote(credential)}"
                print_verbose(f"SSH exec failed, checking auth: {auth_cmd}")
                try:
                    auth_result = subprocess.run(auth_cmd, shell=True, timeout=EXEC_TIMEOUT, capture_output=True)
                    auth_out = auth_result.stdout.decode("utf-8", errors="ignore")
                    print_verbose(f"Auth check output: {auth_out}")
                    # Check for Guest login (not a real authentication)
                    if "(Guest)" in auth_out:
                        print_tool_result(tool, "error", credential, "Guest login (invalid creds)")
                        continue
                    if "[+]" in auth_out and "[-]" not in auth_out:
                        record_result(ip, user, credential, tool, True, False)
                        print_tool_result(tool, "warning", credential, "AUTH OK, command exec failed")
                        auth_successes.append(tool)
                        continue
                except Exception:
                    pass
                print_tool_result(tool, "error", credential)
                continue
            if rc == 0 and out == "":
                print_tool_result(tool, "error", credential)
                continue

        if tool == "mssql":
            if "The EXECUTE permission was denied" in out:
                record_result(ip, user, credential, tool, True, False)
                print_tool_result(tool, "warning", credential, "AUTH OK, command denied (check permissions)")
                auth_successes.append(tool)
                continue
            if "ERROR" in out:
                print_tool_result(tool, "error", credential)
                continue

        # one-shotting using evil-winrm results in a return code of 1
        if rc == 0 or (tool in ("winrm", "winrm-ssl") and rc == 1 and "NoMethodError" in out):
            record_result(ip, user, credential, tool, True, True)
            if RUN_ALL:
                print_tool_result(tool, "success", credential)
                print_output(out)
                continue
            return (tool, out, cmd, auth_successes)

        print_tool_result(tool, "error", credential)

    return (None, None, None, auth_successes)

def execute_for_user(ip, user, credentials, command, tool_list=None):
    """Execute command for a single user with multiple credentials."""
    # Port scan once per user (all creds use same ports)
    if SKIP_PORTSCAN:
        print_verbose(f"{ip}/{user}: Skipping portscan")
        viable_tools = tool_list if tool_list else VALID_TOOLS
    else:
        viable_tools, open_ports = scan_ports_for_tools(ip, tool_list)
        print_verbose(f"{ip}/{user}: Open ports: {sorted(open_ports)}")

        if not viable_tools:
            with print_lock:
                print(f"  {C.RED}No open ports - target down or firewalled{C.RESET}")
            return None

        # Normalize variant names for display (winrm-ssl -> winrm, ldaps -> ldap)
        display_tools = ["winrm" if t == "winrm-ssl" else "ldap" if t == "ldaps" else t for t in viable_tools]
        display_tools = list(dict.fromkeys(display_tools))
        print_verbose(f"{ip}/{user}: Viable tools: {', '.join(display_tools)}")

    # Print user header and table
    print_user_header(user)
    if not DRY_RUN:
        print_table_header()

    # Run each credential
    for cred in credentials:
        if DRY_RUN:
            run_chain(user, ip, cred, command, viable_tools)
            continue

        tool, out, cmd, auth_successes = run_chain(user, ip, cred, command, viable_tools)

        if tool is not None and not RUN_ALL:
            print_tool_result(tool, "success", cred)
            print_verbose(f"Command: {cmd}")
            if tool == "mssql":
                print_warning(f"xp_cmdshell is now enabled on {ip}")
            print_output(out)
            return tool

    return None


def execute_on_target(ip, user_creds, command, tool_list=None):
    """Execute command on a target for all users and their credentials."""
    print_target_header(ip)

    for user, credentials in user_creds.items():
        execute_for_user(ip, user, credentials, command, tool_list)

def parse_args():
    examples = """
examples:
  # Auth check with single credential
  authfinder 10.0.0.1 administrator Password123

  # Auth check across IP range with credential file
  authfinder 10.0.0.1-254 -f creds.txt

  # Test specific services only
  authfinder 10.0.0.1 admin Pass123 --tools ssh,rdp,winrm

  # Use custom port for SSH
  authfinder 10.0.0.1 admin Pass123 --tools ssh --ssh-port 2222

  # LDAP auth on Global Catalog port
  authfinder dc.corp.local admin Pass123 --tools ldap --ldap-port 3268

  # Kerberos auth (requires domain)
  authfinder dc.corp.local admin Pass123 --tools kerberos -d CORP.LOCAL

  # Execute commands (not just auth check)
  authfinder 10.0.0.1 admin Pass123 "whoami /all" -x

  # Dry run to see commands without executing
  authfinder 10.0.0.1 admin Pass123 --dry-run
"""
    parser = argparse.ArgumentParser(
        description="Test authentication across services (SMB, WinRM, SSH, RDP, LDAP, databases, etc.). Use -x to execute commands.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        usage="%(prog)s ip_range username credential [command] [-h] [-v] [-x] [--tools LIST] [-f CRED_FILE]",
        epilog=examples
    )

    parser.add_argument("-v", action="store_true", help="Verbose output")
    parser.add_argument("-o", action="store_true", help="Show successful command output")
    parser.add_argument("--threads", metavar="NUM_THREADS", type=int, default=10, help="Number of concurrent threads")
    parser.add_argument("--timeout", metavar="TIMEOUT_SECONDS", type=int, default=15, help="Number of seconds before commands timeout")
    parser.add_argument("--tools", metavar="LIST", help="Comma-separated list of tools to try")
    parser.add_argument("--first", action="store_true", help="Stop after first successful execution (default: try all tools)")
    parser.add_argument("--skip-portscan", action="store_true", help="Skip port scanning and attempt all tools")
    parser.add_argument("-f", "--file", metavar="CRED_FILE", help="Credential file (username:password per line, colon-separated)")

    parser.add_argument("-x", "--exec", action="store_true", dest="exec_mode", help="Execute commands (default: auth check only)")
    parser.add_argument("--linux", action="store_true", help="Linux-only mode - automates SSH, ignores other tools")
    parser.add_argument("--dry-run", action="store_true", help="Show commands without executing them")
    parser.add_argument("--mask-creds", action="store_true", help="Mask credentials in output (show first few chars only)")
    parser.add_argument("-d", "--domain", metavar="DOMAIN", help="Domain for Kerberos authentication (e.g., CORP.LOCAL)")

    # Custom port options
    ports = parser.add_argument_group("custom ports", "Override default ports for services")
    ports.add_argument("--smb-port", type=int, metavar="PORT", help="SMB port (default: 445)")
    ports.add_argument("--winrm-port", type=int, metavar="PORT", help="WinRM port (default: 5985)")
    ports.add_argument("--ssh-port", type=int, metavar="PORT", help="SSH port (default: 22)")
    ports.add_argument("--rdp-port", type=int, metavar="PORT", help="RDP port (default: 3389)")
    ports.add_argument("--wmi-port", type=int, metavar="PORT", help="WMI port (default: 135)")
    ports.add_argument("--mssql-port", type=int, metavar="PORT", help="MSSQL port (default: 1433)")
    ports.add_argument("--ldap-port", type=int, metavar="PORT", help="LDAP port (default: 389)")
    ports.add_argument("--ftp-port", type=int, metavar="PORT", help="FTP port (default: 21)")
    ports.add_argument("--vnc-port", type=int, metavar="PORT", help="VNC port (default: 5900)")
    ports.add_argument("--kerberos-port", type=int, metavar="PORT", help="Kerberos port (default: 88)")
    ports.add_argument("--postgresql-port", type=int, metavar="PORT", help="PostgreSQL port (default: 5432)")
    ports.add_argument("--mysql-port", type=int, metavar="PORT", help="MySQL port (default: 3306)")
    ports.add_argument("--smtp-port", type=int, metavar="PORT", help="SMTP port (default: 587)")
    ports.add_argument("--imap-port", type=int, metavar="PORT", help="IMAP port (default: 993)")
    ports.add_argument("--redis-port", type=int, metavar="PORT", help="Redis port (default: 6379)")
    ports.add_argument("--ipmi-port", type=int, metavar="PORT", help="IPMI port (default: 623)")

    parser.add_argument("ip_range", help="IP range (e.g., 192.168.1.1-254)")
    parser.add_argument("username", nargs="?", help="Username or file containing usernames (one per line)")
    parser.add_argument("credential", nargs="?", help="Password/NT hash or file containing credentials (one per line)")
    parser.add_argument("command", nargs="*", help="Command to run (default: whoami)")

    args = parser.parse_args()

    if args.file and (args.username or args.credential):
        parser.error("Cannot specify username/password when using -f")

    if not args.file and (not args.username or not args.credential):
        parser.error("Must supply either -f FILE or username and credential")

    return args



def check_dependencies():
    """Check if required tools are installed."""
    global IMPACKET_PREFIX, NXC_CMD, WINRM_CMD

    # Check impacket (either impacket-psexec or psexec.py)
    r1 = shutil.which("impacket-psexec")
    r2 = shutil.which("psexec.py")
    if r1:
        IMPACKET_PREFIX = "impacket-"
    elif r2:
        IMPACKET_PREFIX = ""
    elif not LINUX_MODE:
        print_error("impacket not found. Install with: pipx install impacket")
        sys.exit(1)
    
    # Check nxc/crackmapexec
    r1 = shutil.which("nxc")
    r2 = shutil.which("netexec")
    r3 = shutil.which("crackmapexec")
    if r1:
        NXC_CMD = "nxc"
    elif r2:
        NXC_CMD = "netexec"
    elif r3:
        NXC_CMD = "crackmapexec"
    else:
        print_error("netexec not found. Install with: pipx install git+https://github.com/Pennyw0rth/NetExec")
        sys.exit(1)

    # Check evil-winrm
    if shutil.which("evil-winrm"):
        WINRM_CMD = "evil-winrm"
    else:
        # default in exegol
        base = "/usr/local/rvm/gems"
        if os.path.isdir(base):
            for d in os.listdir(base):
                if d.endswith("@evil-winrm"):
                    WINRM_CMD = f"{base}/{d}/wrappers/evil-winrm"
                    break
    if not WINRM_CMD and not LINUX_MODE:
        print_error("evil-winrm not found. Install with: gem install evil-winrm")
        sys.exit(1)

    # Check optional tools for new protocols (warn but don't fail)
    OPTIONAL_TOOLS = {
        "psql": "postgresql",
        "mysql": "mysql",
        "redis-cli": "redis",
        "ipmitool": "ipmi"
    }
    missing = []
    for cmd, proto in OPTIONAL_TOOLS.items():
        if not shutil.which(cmd):
            missing.append(proto)
    if missing:
        print_verbose(f"Optional tools not found (some protocols unavailable): {', '.join(missing)}")


def impacket_cmd(tool):
    """Return the correct impacket command name based on install type."""
    if IMPACKET_PREFIX:
        return f"impacket-{tool}"
    return f"{tool}.py"

def main():
    global VERBOSE, OUTPUT, MAX_THREADS, EXEC_TIMEOUT, RUN_ALL, SKIP_PORTSCAN, TOOLS_SPECIFIED, LINUX_MODE, DRY_RUN, MASK_CREDS, DOMAIN, EXEC_MODE, CUSTOM_PORTS

    check_dependencies()

    args = parse_args()

    VERBOSE = args.v
    OUTPUT = args.o
    MAX_THREADS = args.threads if args.threads > 0 else 1
    EXEC_TIMEOUT = args.timeout
    RUN_ALL = not args.first  # Default is to run all tools
    SKIP_PORTSCAN = args.skip_portscan
    LINUX_MODE = args.linux
    DRY_RUN = args.dry_run
    MASK_CREDS = args.mask_creds
    DOMAIN = args.domain
    EXEC_MODE = args.exec_mode

    # Build custom ports dict from args
    CUSTOM_PORTS = {}
    port_mappings = [
        ("smb_port", "smb"), ("winrm_port", "winrm"), ("ssh_port", "ssh"),
        ("rdp_port", "rdp"), ("wmi_port", "wmi"), ("mssql_port", "mssql"),
        ("ldap_port", "ldap"), ("ftp_port", "ftp"), ("vnc_port", "vnc"),
        ("kerberos_port", "kerberos"), ("postgresql_port", "postgresql"),
        ("mysql_port", "mysql"), ("smtp_port", "smtp"), ("imap_port", "imap"),
        ("redis_port", "redis"), ("ipmi_port", "ipmi")
    ]
    for arg_name, tool_name in port_mappings:
        port = getattr(args, arg_name, None)
        if port:
            CUSTOM_PORTS[tool_name] = port

    if args.file:
        credential_list = load_credential_file(args.file)
    else:
        usernames = resolve_argument(args.username)
        credentials = resolve_argument(args.credential)
        credential_list = [(u, c) for u in usernames for c in credentials]

    # Group credentials by user for cleaner output
    user_creds = OrderedDict()
    for user, cred in credential_list:
        if user not in user_creds:
            user_creds[user] = []
        user_creds[user].append(cred)

    if args.ip_range.endswith('.txt'):
        ips = []
        with open(args.ip_range) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    ips.extend(parse_ip_range(line))
    else:
        ips = parse_ip_range(args.ip_range)

    if len(ips) < MAX_THREADS and not args.threads:
        MAX_THREADS = len(ips)

    if args.linux:
        if args.tools:
            print_warning("Tools (--tools) cannot be specified alongside Linux-mode (--linux), as only SSH is supported. Continuing with SSH...")
        args.tools = "ssh"

    if args.tools:
        tool_list = parse_tools_list(args.tools)
        TOOLS_SPECIFIED = True
    else:
        tool_list = None

    command = " ".join(args.command) if args.command else "whoami"

    # Print configuration section
    print_section("Configuration")
    print_info(f"Mode: {'Command Execution' if EXEC_MODE else 'Auth Check Only'}")
    print_info(f"Targets: {len(ips)} IP(s)")
    print_info(f"Credentials: {len(credential_list)} set(s)")
    print_info(f"Threads: {MAX_THREADS}")
    if EXEC_MODE:
        print_info(f"Command: {command}")
    if tool_list:
        print_info(f"Tools: {', '.join(tool_list)}")
    if CUSTOM_PORTS:
        ports_str = ", ".join(f"{k}:{v}" for k, v in CUSTOM_PORTS.items())
        print_info(f"Custom ports: {ports_str}")
    if DRY_RUN:
        print_warning("DRY-RUN MODE - Commands will be shown but not executed.")
    if args.skip_portscan:
        print_warning("Port scanning disabled (--skip-portscan). All tools will be attempted.")
    if EXEC_MODE:
        if not OUTPUT and not DRY_RUN:
            print_warning("Output disabled. Run with -o to see successful command output.")
        elif not LINUX_MODE and not DRY_RUN:
            print_warning("Output enabled. This WILL trip AV for certain tools.")

    print_section("Execution")

    # Process targets - parallelize across targets but keep each target's output grouped
    if len(ips) == 1:
        # Single target - run directly
        execute_on_target(ips[0], user_creds, command, tool_list)
    else:
        # Multiple targets - parallelize
        futures = []
        with ThreadPoolExecutor(max_workers=min(MAX_THREADS, len(ips))) as executor:
            for ip in ips:
                futures.append(
                    executor.submit(execute_on_target, ip, user_creds, command, tool_list)
                )

            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print_warning(f"Exception: {e}")

    # Print summary of successful authentications
    if not DRY_RUN:
        print_section("Summary")
        print_summary()

    print_section("Complete")

if __name__ == "__main__":
    main()