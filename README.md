# IPAM/VLAN Manager TUI

A terminal-based IP Address Management (IPAM) and VLAN manager with a retro curses interface. Can run standalone in a terminal or be served via a web browser using the included xterm.js web server.

## Purpose

I am an infrastructure engineer. This project came about as a way for me to fill the gap for an IPAM that is easy to set up, easy to use, and easy to move around.  I had been using [nipap](https://spritelink.github.io/NIPAP/) for a while, which was the most lightweight IPAM I had seen up to that point beyond using a spreadsheet, and it was still more machinery than I wanted to deal with.  Considering the amount of time I spend ssh'ing into things, having a TUI IPAM seemed reasonable.

*AI use disclosure:* This project made heavy use of Claude Opus in its development.

## Features

- **Multi-User Support** — Login system with role-based access control (Admin/Editor/Viewer)
- **VLAN Management** — Create, edit, delete VLANs with routed/unrouted designation
- **Subnet Management** — Organize subnets within VLANs, multiple CIDR ranges per subnet
- **IP Address Tracking** — View in-use and unused IPs with attribute inheritance
- **Flexible Attributes** — Standard fields plus custom attributes
- **Search** — Find VLANs, subnets, and IPs by CIDR, customer, or location
- **Import/Export** — XLSX spreadsheet support for bulk operations
- **Snapshots & Rollback** — Automatic snapshots with point-in-time recovery
- **Audit Log** — Track all changes with timestamps and user attribution
- **Web Interface** — Optional browser-based access via xterm.js

## Quick Start

### Using uv (Recommended)

```bash
# Install uv if you haven't already
curl -LsSf https://astral.sh/uv/install.sh | sh

# Create virtual environment and install dependencies
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
uv pip install -r requirements.txt

# Run the TUI directly
python ipam-tui.py mynetwork.db

# Or run via web server
python ipam-web.py mynetwork.db
```

### Using pip

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt

python ipam-tui.py mynetwork.db
```

## Standalone TUI Usage

Run directly in any terminal emulator:

```bash
python ipam-tui.py <database.db> [options]
```

**Options:**
| Flag | Description |
|------|-------------|
| `--bios` | Show retro BIOS POST sequence on startup |
| `--reset-colors` | Reset color scheme to default green |
| `--reset-admin` | Reset admin password to 'admin' |
| `--version` | Print version and exit |

**Examples:**
```bash
# Basic usage
python ipam-tui.py network.db

# With BIOS boot sequence
python ipam-tui.py network.db --bios

# Reset admin password if locked out
python ipam-tui.py network.db --reset-admin
```

## Web Server Usage

Serve the TUI in a browser via xterm.js:

```bash
python ipam-web.py <database.db> [options]
```

**Options:**
| Flag | Description |
|------|-------------|
| `--port PORT` | Server port (default: 8080) |
| `--host HOST` | Bind address (default: 0.0.0.0) |
| `--exports-dir DIR` | Directory for exports (default: ./exports) |
| `-- FLAGS` | Pass additional flags to TUI (after `--`) |
| `--version` | Print version and exit |

**Examples:**
```bash
# Basic web server
python ipam-web.py network.db

# Custom port
python ipam-web.py network.db --port 3000

# With BIOS sequence for all sessions
python ipam-web.py network.db -- --bios

# Bind to localhost only
python ipam-web.py network.db --host 127.0.0.1 --port 8080
```

**URLs:**
- Terminal: `http://localhost:8080/`
- Exports: `http://localhost:8080/exports/`

Each browser tab/session spawns an independent TUI instance with its own login. Exported files are available at `/exports/` and are automatically cleaned up when sessions end.

## Default Credentials

On first run, a default admin account is created:
- **Username:** `admin`
- **Password:** `admin`

⚠️ **Change this password after first login.** ⚠️  

## User Roles

| Role | Capabilities |
|------|--------------|
| **Admin** | Full access including user management, snapshots, database settings |
| **Editor** | Create, edit, delete VLANs/subnets/IPs; export/import; view audit log |
| **Viewer** | Read-only: search, list, export, view audit log |

## Navigation

| Key | Action |
|-----|--------|
| `↑`/`↓` or `j`/`k` | Move selection |
| `PgUp`/`PgDn` | Page through lists |
| `Enter` | Select/confirm |
| `q` | Back/cancel |
| `Esc` | Return to main menu |

## Data Model

```
VLAN
 └── Subnet (Broadcast Domain)
      ├── CIDR Range(s)
      └── IP Addresses
           └── Attributes
```

Attributes inherit downward: VLAN → Subnet → IP. Setting an attribute at the IP level overrides inherited values.

## Deploying as a Linux Login Shell

The TUI can be deployed as the login shell for a dedicated system user so that SSH connections drop directly into the IPAM interface. When the user quits the TUI, the SSH session ends.

### 1. Create the wrapper script

```bash
sudo mkdir -p /opt/ipam
sudo cp ipam-tui.py /opt/ipam/
sudo cp requirements.txt /opt/ipam/

# Install dependencies system-wide (or use a venv — see note below)
pip install openpyxl

# Create the login wrapper
sudo tee /opt/ipam/ipam-shell.sh > /dev/null << 'EOF'
#!/bin/bash
# IPAM TUI login shell wrapper
DB="/opt/ipam/ipam.db"

# Reset terminal on exit (clean up curses)
trap 'reset' EXIT

# Launch the TUI
exec python3 /opt/ipam/ipam-tui.py "$DB"
EOF

sudo chmod 755 /opt/ipam/ipam-shell.sh
```

### 2. Register the shell and create the user

```bash
# Add to valid login shells
echo '/opt/ipam/ipam-shell.sh' | sudo tee -a /etc/shells

# Create dedicated user with the IPAM shell
sudo useradd -m -s /opt/ipam/ipam-shell.sh ipam

# Set an SSH password (or configure key-based auth instead)
sudo passwd ipam
```

Users connect with `ssh ipam@yourserver` and land directly in the TUI login screen. The TUI handles its own authentication — the system account is just the transport.

### 3. File permissions

```bash
# The ipam user needs read/write on the database
sudo chown ipam:ipam /opt/ipam/ipam.db
sudo chmod 660 /opt/ipam/ipam.db

# Scripts are read/execute for everyone
sudo chmod 755 /opt/ipam/ipam-tui.py
```

### Alternative: ForceCommand (per-user or per-group)

If you'd rather use existing system accounts instead of a dedicated `ipam` user, you can restrict specific users or groups via `sshd_config`:

```bash
# /etc/ssh/sshd_config (add at the end)
Match Group ipam-users
    ForceCommand /opt/ipam/ipam-shell.sh
    X11Forwarding no
    AllowTcpForwarding no
```

```bash
sudo groupadd ipam-users
sudo usermod -aG ipam-users jsmith
sudo systemctl reload sshd
```

Now anyone in the `ipam-users` group gets the TUI on SSH login regardless of their normal shell.

### Using a virtual environment

If you prefer not to install packages system-wide, use a venv inside the wrapper:

```bash
cd /opt/ipam
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Then change the wrapper script to use the venv Python:

```bash
exec /opt/ipam/.venv/bin/python3 /opt/ipam/ipam-tui.py "$DB"
```

### Notes

- Each SSH session spawns an independent TUI instance. Concurrent sessions are safe; SQLite handles locking.
- Exported XLSX files land in the working directory of the shell process. Set `cd /opt/ipam/exports` in the wrapper if you want them in a predictable location.
- To prevent the user from escaping to a shell via `~C` or other SSH escapes, the `ForceCommand` approach is more restrictive than setting a login shell.

## Files

- `ipam-tui.py` — Standalone terminal application
- `ipam-web.py` — Web server wrapper (requires aiohttp)
- `requirements.txt` — Python dependencies
- `seed_demo.py` — Demo database seeder (used by Codespaces)
- `example_data.xlsx` — Sample data for demo environments
- `.devcontainer/` — GitHub Codespaces configuration
- `*.db` — SQLite database (created automatically)

All data is stored in a single SQLite database file including user credentials (hashed), snapshots, and audit logs.

## License

MIT
