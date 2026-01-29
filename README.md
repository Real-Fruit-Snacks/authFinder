# AuthFinder

[![PyPI version](https://img.shields.io/pypi/v/authfinder)](https://pypi.org/project/authfinder/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

Test where credentials are valid across Windows and Linux systems using multiple authentication methods. Automatically tries different techniques until one succeeds.

This is a fork of [KhaelK138/authfinder](https://github.com/KhaelK138/authfinder). Built as a wrapper around [NetExec](https://github.com/Pennyw0rth/NetExec), [Impacket](https://github.com/fortra/impacket), and [Evil-WinRM](https://github.com/Hackplayers/evil-winrm).

## Quick Start

```bash
# Install
pipx install authfinder

# Test credentials on a single host
authfinder 192.168.1.10 administrator Password123 whoami

# Test across an IP range
authfinder 192.168.1.1-50 admin Pass123 whoami

# Test with NTLM hash
authfinder 10.0.0.1-10 admin :aabbccdd11223344aabbccdd11223344 whoami
```

## Features

- **Multiple Authentication Methods** - Automatically tries WinRM, PSExec, SMBExec, WMI, AtExec, RDP, SSH, and MSSQL
- **Smart Port Scanning** - Pre-scans ports to only attempt viable methods
- **Multi-threaded** - Test credentials across multiple hosts simultaneously
- **Pass-the-Hash** - Use NTLM hashes directly as credentials
- **Credential Files** - Test multiple username/password combinations from a file
- **Linux Support** - Use `--linux` mode for SSH-only testing

## Installation

```bash
pipx install authfinder
```

### External Dependencies

AuthFinder requires these tools to be installed separately:

| Tool | Install Command | Provides |
|------|-----------------|----------|
| Impacket | `pipx install impacket` | PSExec, AtExec, MSSQL |
| NetExec | `pipx install git+https://github.com/Pennyw0rth/NetExec` | SMBExec, WMI, RDP, SSH |
| Evil-WinRM | `gem install evil-winrm` | WinRM |

## How It Works

AuthFinder scans target ports and attempts authentication methods based on what's available:

| Port | Methods |
|------|---------|
| 445 | PSExec, SMBExec, AtExec |
| 135 | WMI |
| 5985/5986 | WinRM |
| 3389 | RDP |
| 22 | SSH |
| 1433 | MSSQL |

For each host, it tries methods in order until one succeeds (or all methods with `--run-all`). Results show both **authentication success** and **command execution success** separately.

## Usage

### Basic Syntax

```
authfinder <targets> <username> <credential> <command> [options]
```

The `username` and `credential` arguments accept either literal values or file paths. If a file path is provided, values are read from the file (one per line). When both are files, all combinations are tested.

### Target Formats

| Format | Example | Description |
|--------|---------|-------------|
| Single IP | `192.168.1.10` | One host |
| Comma-separated | `192.168.1.15,17,29` | Multiple hosts |
| Range | `192.168.1.1-254` | IP range |
| Multi-octet range | `10.0.1-5.10-20` | All combinations |
| File | `targets.txt` | One target per line |

### Credential Input Methods

**Option 1: Positional arguments (with optional file support)**

```bash
# Literal values
authfinder 192.168.1.10 admin Password123 whoami

# Username from file, single password
authfinder 192.168.1.10 users.txt Password123 whoami

# Single username, passwords from file
authfinder 192.168.1.10 admin passwords.txt whoami

# Both from files (tests all combinations)
authfinder 192.168.1.10 users.txt passwords.txt whoami
```

Files contain one value per line. Blank lines and `#` comments are ignored.

**Option 2: Credential file with `-f` (username:password pairs)**

```bash
authfinder 192.168.1.10 -f creds.txt whoami
```

File format is `username:password` per line (colon-separated). Only the first colon is the delimiter, so passwords can contain colons:

```
# Comments start with #
administrator:Password123!
admin:Pass123
backup_admin::aabbccdd11223344aabbccdd11223344
```

### Options

| Option | Description |
|--------|-------------|
| `-v` | Verbose output (show all tool attempts) |
| `-o` | Show command output (may trigger AV) |
| `-f <file>` | Use credential file |
| `--threads <n>` | Concurrent threads (default: 10) |
| `--tools <list>` | Comma-separated list of tools to try |
| `--timeout <sec>` | Command timeout (default: 15) |
| `--run-all` | Try all methods, don't stop at first success |
| `--skip-portscan` | Skip port scan, attempt all tools |
| `--linux` | Linux mode (SSH only) |

### Examples

```bash
# Test single credential across a subnet
authfinder 192.168.1.1-254 admin Password123 whoami

# Use credential file with verbose output
authfinder 10.0.0.1-50 -f creds.txt -v whoami

# Only try specific tools
authfinder 192.168.1.10 admin Pass123 --tools winrm,psexec whoami

# Test all methods (don't stop at first success)
authfinder 192.168.1.10 admin Pass123 --run-all whoami

# Linux targets via SSH
authfinder 10.0.0.1-10 root password --linux id
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Disclaimer

This tool is intended for **authorized security assessments only**. Ensure you have proper authorization before testing any systems you do not own.
