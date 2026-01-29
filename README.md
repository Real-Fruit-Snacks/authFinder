# AuthFinder

[![PyPI version](https://img.shields.io/pypi/v/authfinder)](https://pypi.org/project/authfinder/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

Test authentication across Windows and Linux services. Supports SMB, WinRM, SSH, RDP, LDAP, Kerberos, databases, and more.

This is a fork of [KhaelK138/authfinder](https://github.com/KhaelK138/authfinder). Built as a wrapper around [NetExec](https://github.com/Pennyw0rth/NetExec), [Impacket](https://github.com/fortra/impacket), and [Evil-WinRM](https://github.com/Hackplayers/evil-winrm).

## Quick Start

```bash
# Install
pipx install authfinder

# Test credentials on a single host (auth check only)
authfinder 192.168.1.10 administrator Password123

# Test across an IP range
authfinder 192.168.1.1-50 admin Pass123

# Test specific services
authfinder 10.0.0.1 admin Pass123 --tools ldap,smb,winrm

# Execute commands (opt-in with -x)
authfinder 10.0.0.1 admin Pass123 "whoami /all" -x
```

## Features

- **Auth Check by Default** - Tests if credentials are valid without executing commands
- **19 Authentication Methods** - SMB, WinRM, WMI, SSH, RDP, MSSQL, LDAP, Kerberos, FTP, VNC, PostgreSQL, MySQL, SMTP, IMAP, Redis, IPMI
- **Smart Port Scanning** - Pre-scans ports to only attempt viable methods
- **Custom Ports** - Override default ports with `--ssh-port`, `--ldap-port`, etc.
- **Multi-threaded** - Test credentials across multiple hosts simultaneously
- **Pass-the-Hash** - Use NTLM hashes directly as credentials
- **Command Execution** - Optionally execute commands with `-x` flag

## Installation

```bash
pipx install authfinder
```

### External Dependencies

AuthFinder requires these tools to be installed separately:

| Tool | Install Command | Provides |
|------|-----------------|----------|
| Impacket | `pipx install impacket` | PSExec, AtExec, MSSQL, Kerberos |
| NetExec | `pipx install git+https://github.com/Pennyw0rth/NetExec` | SMB, WMI, RDP, SSH, LDAP, FTP, VNC, WinRM, MSSQL |
| Evil-WinRM | `gem install evil-winrm` | WinRM (exec mode) |

Optional tools for additional protocols:
- `psql` - PostgreSQL authentication
- `mysql` - MySQL authentication
- `redis-cli` - Redis authentication
- `ipmitool` - IPMI authentication

## Supported Services

| Port | Service | Auth | Exec | Notes |
|------|---------|------|------|-------|
| 445 | SMB (psexec/smbexec/atexec) | Yes | Yes | Pass-the-hash supported |
| 135 | WMI | Yes | Yes | Pass-the-hash supported |
| 5985/5986 | WinRM | Yes | Yes | Pass-the-hash supported |
| 3389 | RDP | Yes | Yes | Pass-the-hash supported |
| 22 | SSH | Yes | Yes | Password only |
| 1433 | MSSQL | Yes | Yes | Pass-the-hash supported |
| 389/636 | LDAP/LDAPS | Yes | No | Pass-the-hash supported |
| 88 | Kerberos | Yes | No | Requires `--domain` |
| 21 | FTP | Yes | No | Password only |
| 5900 | VNC | Yes | No | Password only |
| 5432 | PostgreSQL | Yes | No | Password only |
| 3306 | MySQL | Yes | No | Password only |
| 587/993 | SMTP/IMAP | Yes | No | Password only |
| 6379 | Redis | Yes | No | Password only |
| 623 | IPMI | Yes | No | Password only |

## Usage

### Basic Syntax

```
authfinder <targets> <username> <credential> [command] [options]
```

By default, AuthFinder only tests authentication. Use `-x` to execute commands.

### Examples

```bash
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
```

### Target Formats

| Format | Example | Description |
|--------|---------|-------------|
| Single IP | `192.168.1.10` | One host |
| Comma-separated | `192.168.1.15,17,29` | Multiple hosts |
| Range | `192.168.1.1-254` | IP range |
| Multi-octet range | `10.0.1-5.10-20` | All combinations |
| File | `targets.txt` | One target per line |

### Credential Input

**Option 1: Positional arguments**

```bash
# Literal values
authfinder 192.168.1.10 admin Password123

# From files (tests all combinations)
authfinder 192.168.1.10 users.txt passwords.txt
```

**Option 2: Credential file with `-f`**

```bash
authfinder 192.168.1.10 -f creds.txt
```

File format (`username:password` per line):
```
administrator:Password123!
admin:Pass123
backup_admin::aabbccdd11223344aabbccdd11223344
```

### Options

| Option | Description |
|--------|-------------|
| `-x, --exec` | Execute commands (default: auth check only) |
| `-v` | Verbose output |
| `-o` | Show command output (exec mode only) |
| `-f <file>` | Use credential file |
| `-d, --domain` | Domain for Kerberos auth |
| `--tools <list>` | Comma-separated list of tools |
| `--threads <n>` | Concurrent threads (default: 10) |
| `--timeout <sec>` | Command timeout (default: 15) |
| `--first` | Stop after first success |
| `--skip-portscan` | Skip port scan, attempt all tools |
| `--linux` | Linux mode (SSH only) |
| `--dry-run` | Show commands without executing |
| `--mask-creds` | Mask credentials in output |

### Custom Port Options

| Option | Default | Description |
|--------|---------|-------------|
| `--smb-port` | 445 | SMB (psexec/smbexec/atexec) |
| `--winrm-port` | 5985 | WinRM |
| `--ssh-port` | 22 | SSH |
| `--rdp-port` | 3389 | RDP |
| `--wmi-port` | 135 | WMI |
| `--mssql-port` | 1433 | MSSQL |
| `--ldap-port` | 389 | LDAP |
| `--kerberos-port` | 88 | Kerberos |
| `--ftp-port` | 21 | FTP |
| `--vnc-port` | 5900 | VNC |
| `--postgresql-port` | 5432 | PostgreSQL |
| `--mysql-port` | 3306 | MySQL |
| `--smtp-port` | 587 | SMTP |
| `--imap-port` | 993 | IMAP |
| `--redis-port` | 6379 | Redis |
| `--ipmi-port` | 623 | IPMI |

## Example Output

```
 ============================================================
|    Configuration                                          |
 ============================================================
[*] Mode: Auth Check Only
[*] Targets: 1 IP(s)
[*] Credentials: 2 set(s)
[*] Tools: ldap, smb, winrm

 ============================================================
|    Target: 10.0.0.1                                       |
 ============================================================

   ========================================================
  |    User: administrator                                 |
   ========================================================
  Credential               Service      Auth     Exec       Notes
  ──────────────────────── ──────────── ──────── ────────── ────────────
  Password123              ldap         OK       N/A
  Password123              smb          OK       N/A
  Password123              winrm        OK       N/A

 ============================================================
|    Summary                                                |
 ============================================================

Target           Username         Password             Service      Result
──────────────── ──────────────── ──────────────────── ──────────── ────────
10.0.0.1         administrator    Password123          ldap         Auth
10.0.0.1         administrator    Password123          smb          Auth
10.0.0.1         administrator    Password123          winrm        Auth
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Disclaimer

This tool is intended for **authorized security assessments only**. Ensure you have proper authorization before testing any systems you do not own.
