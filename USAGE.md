# Usage Guide

This is a hands-on tutorial that walks through every major feature. By the end you'll know how to manage VLANs, subnets, IPs, users, and snapshots.

We'll use a throwaway database called `tutorial.db` throughout. **When you're ready to use this for real, just delete `tutorial.db` and start fresh with your production database name.** Nothing carries over — each `.db` file is completely independent.

## Starting Up

```bash
python ipam-tui.py tutorial.db
```

On first launch the database is created automatically and a default admin account is set up.

Log in with:
- **Username:** `admin`
- **Password:** `admin`

You'll land on the main menu:

```
Create VLAN
Create Subnet
Search
List
Owned Subnets
Export All VLANs
Import from XLSX
Audit Log
Configure
Quit
```

Use the arrow keys (or `j`/`k`) to move, `Enter` to select. `q` goes back one level, `Esc` jumps straight to the main menu from anywhere.

## First Things First: Change Your Password and Name the Database

Before anything else, go to **Configure > Change My Password**. Enter the current password (`admin`), then set a new one. Passwords must be at least 16 characters and include uppercase, lowercase, a number, and a special character. Passphrases work well — something like `Tango4$emotional$BAGPIPES`.

While you're in **Configure**, go to **Database Name** and type a name like `Tutorial`. This shows in the header bar on every screen so you always know which database you're working in. Useful if you end up managing multiple environments.

## Importing Data from a Spreadsheet

If you have existing data in a spreadsheet, import it first. Place your `.xlsx` file in the same directory as `ipam-tui.py`, then from the main menu select **Import from XLSX**.

You'll see a file picker listing all `.xlsx` files in the current directory. Select your file, then choose an import mode:

- **Interactive** — prompts you yes/no for every conflict between the spreadsheet and existing data
- **Prefer DB** — keeps existing values, only adds new data
- **Prefer Import** — overwrites conflicts with spreadsheet values, but leaves DB-only attributes untouched
- **Overwrite** — replaces everything with the spreadsheet data, clearing any attributes not in the import

A snapshot is taken automatically before the import starts, so you can always roll it back.

The included `example_data.xlsx` is a good file to import into your tutorial database to have something to look at.

## Creating VLANs

From the main menu, select **Create VLAN**.

Enter a VLAN number (1–4094). You'll be asked for a name, whether it's routed, an uplink, and attributes like Customer, Location, and Comment.

**Routed vs. unrouted:** A routed VLAN has its subnets participate in IP routing, which means its CIDR ranges must not overlap with CIDR ranges in any other routed VLAN — or with other subnets in the same routed VLAN. This strict enforcement prevents double-counting and routing conflicts. Unrouted VLANs (the default) have no overlap restrictions — this is normal for isolated layer-2 segments, lab networks, or environments where overlapping address space is intentional.

Once created, you can find your VLAN through **List > VLANs** or **Search > VLAN** (by number).

## The VLAN Screen

Selecting a VLAN opens a split view. The left side shows VLAN details and attributes. The right side lists its subnets.

Keys on this screen:

| Key | Action |
|-----|--------|
| `Enter` | Open the selected subnet |
| `a` | Edit VLAN attributes |
| `n` | Add a new subnet |
| `r` | Toggle routed/unrouted |
| `s` | Toggle sort order (by name or by CIDR) |
| `x` | Export this VLAN to XLSX |
| `d` | Delete this VLAN (danger — requires confirmation) |
| `q` | Go back |

## Creating Subnets

You can create a subnet two ways:

1. From the main menu: **Create Subnet** — you'll pick a VLAN first, then enter a name and CIDR.
2. From inside a VLAN screen: press `n` to add a subnet directly.

A subnet needs at least one CIDR range (like `10.0.0.0/24`). You can add more ranges later — a single subnet can span multiple CIDRs. The ranges cannot overlap with each other within the same subnet, and if the parent VLAN is routed, they can't overlap with any range in any routed VLAN — including other subnets in the same VLAN.

After creating the subnet you'll be prompted for attributes (Customer, Location, Comment). These are inheritable — any IP in this subnet will inherit these values unless it has its own override.

## The Subnet Screen

Selecting a subnet opens another split view. Left side shows subnet details, CIDR ranges, and attributes. Right side shows IP addresses.

Keys on this screen:

| Key | Action |
|-----|--------|
| `Enter` | Edit the selected IP's attributes |
| `t` | Toggle between in-use and unused IPs |
| `e` | Edit subnet attributes |
| `n` | Rename the subnet |
| `m` | Move the subnet to a different VLAN |
| `d` | Delete this subnet (removes all IPs and attributes) |
| `q` | Go back |

### In-Use vs. Unused

By default you see "in-use" IPs — addresses that have at least one attribute set that differs from what they'd inherit from the subnet. Press `t` to switch to the "unused" view, which shows every IP in the CIDR range that doesn't have custom attributes. This is how you find the next available address.

For large subnets (bigger than a /20), the unused view is disabled to avoid enumerating millions of addresses. You can still search for specific IPs.

## Working with IP Addresses

Select any IP from the subnet view and press `Enter` to edit its attributes. You'll see a form with the standard fields:

- **Customer** — who is using this IP
- **Location** — where the device is
- **Comment** — free-text notes
- **Asset** — asset tag or serial number
- **Interface** — the interface name (e.g., `eth0`, `Gi0/1`)
- **Network Connection** — cable ID, port number, etc.

Fields that match the inherited subnet/VLAN value are shown but empty — you only need to fill in values that differ. Press `s` to save, `a` to add a custom key beyond the standard ones, `q` to cancel.

You can also get to an IP directly from the main menu via **Search > IP address** or through **List > IP addresses (stored)**.

## Searching

The search menu offers five modes:

- **VLAN** — search by VLAN number, opens the VLAN screen directly
- **IP address** — search by IP, lands you in the containing subnet
- **CIDR** — search by network range (works both directions — searching a /16 finds all /24s inside it, and searching a /25 finds the /24 that contains it)
- **Customer** — search across all VLANs and subnets by customer name
- **Location** — same, by location

Customer and Location searches support three match modes: regex, starts-with, and contains. Results show matching VLANs and subnets — select one to open it.

## Exporting

**Export All VLANs** from the main menu creates a single XLSX file with one sheet per VLAN. Each sheet contains the VLAN metadata, subnet names, CIDR ranges, IP addresses, and all attributes.

You can also export a single VLAN from inside its screen by pressing `x`.

Export files are saved in the current working directory. You'll be prompted for a filename or can leave it blank for an auto-generated timestamp name.

## Owned Subnets

If your datacenter has purchased public IP blocks (e.g., a /24 from your ISP or RIR), the **Owned Subnets** feature lets you track how much of that space you've allocated.

From the main menu, select **Owned Subnets**. This is a top-level section that lives outside the VLAN hierarchy entirely. Owned subnets are not broadcast domains — they're a record of address space you own, with a utilization view that cross-references your routed VLANs.

### Adding an Owned Subnet

Press `n` to add a new block. Enter the CIDR (e.g., `198.51.100.0/24`) and an optional label (e.g., `ISP Allocation - Jan 2025`).

Two restrictions apply:

- **No RFC 1918 space.** Private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) are rejected. Tracking "ownership" of reusable private space doesn't mean anything — this feature is specifically for public address space you've paid for and need to account for.
- **No overlaps.** Owned subnets cannot overlap with each other. If you buy additional space that expands an existing block, remove the old entry and add the new larger one. The audit log preserves the history.

### The Owned Subnets List

The list shows each owned CIDR with its label and a utilization summary: `allocated/total (percentage)`. Allocated addresses are counted by looking at CIDR ranges in routed VLANs that fall within the owned block.

Keys on this screen:

| Key | Action |
|-----|--------|
| `Enter` | Open the detail view |
| `n` | Add a new owned subnet |
| `e` | Rename the selected entry |
| `d` | Remove the selected entry |
| `q` | Go back |

### The Detail View

Select an owned subnet and press `Enter` to see the detail screen. This is a split view:

**Left panel** shows the CIDR, label, total/allocated/available address counts, a utilization bar, and a list of available (unallocated) blocks. The available blocks are computed automatically — if you own a /24 and have allocated a /26 and a /25 out of it, the detail view shows you the remaining /26 that's still free.

**Right panel** lists every routed VLAN subnet that falls within the owned range, along with its Customer and Location. Select any allocation and press `Enter` to jump directly to that subnet's screen.

### How Ownership Changes Work

Owned subnets are a flat list — there's no hierarchy, no exclusions, no special states. The list represents what you own right now.

- **Buy a /29** → add it.
- **Later buy the rest of the /24** → remove the /29, add the /24.
- **Later sell a /26 out of it** → remove the /24, add back the ranges you kept.

The audit log captures every addition and removal, so you always have a paper trail of how your ownership changed over time.

## The Audit Log

Every significant action is logged — VLAN creation, subnet deletion, imports, user logins, snapshots, and more. Select **Audit Log** from the main menu to browse it.

The log shows a timestamped list of entries. Entries marked with `✓` have an associated snapshot that you can roll back to.

Keys in the audit log:

| Key | Action |
|-----|--------|
| `f` | Filter — toggle between all entries and restorable-only |
| `s` | Sort — toggle newest-first / oldest-first |
| `Enter` | Roll back to the selected snapshot |

### What Creates a Snapshot

Not every action creates one. Snapshots are created before:

- Creating a VLAN
- Deleting a VLAN
- Deleting a subnet
- Adding or removing an owned subnet
- Importing from XLSX
- Restoring a previous snapshot (yes, you can roll back a rollback)

Actions like editing attributes, adding IPs, or changing settings are logged but don't have snapshots. This keeps the database from growing too quickly while still protecting against the destructive operations.

### Rolling Back

Select any entry with a `✓`, press `Enter`, and confirm. The current database is backed up to a `.backup_TIMESTAMP` file first, then the database is restored to the state captured in that snapshot. Snapshots and audit log entries are preserved across rollbacks so you don't lose your history.

## Managing Users

Go to **Configure > User Management** (admin only). You'll see the list of existing users. Select one to change their role, reset their password, or delete them.

Select **+ Add New User** to create a new account. You'll enter a username (2–64 characters, letters/numbers/`.`/`-`/`_` only), a password, and a role:

- **Admin** — full access including user management and database settings
- **Editor** — can create, edit, and delete VLANs/subnets/IPs, import/export, view audit log
- **Viewer** — read-only access (search, list, export, view audit log)

You can't delete your own account or the last remaining admin.

## Deleting Things

Deletion works from the bottom up:

**Deleting a subnet** (press `d` from the subnet screen) removes the subnet, all its CIDR ranges, all IP addresses in it, and all their attributes. A snapshot is taken first. You'll see a confirmation prompt.

**Deleting a VLAN** (press `d` from the VLAN screen) is the big one. It removes the VLAN, all its subnets, all IPs in those subnets, and all associated attributes. This requires a danger confirmation — you must type `yes` (not just press Enter) to proceed. A snapshot is taken first, and you'll see a count of exactly how many subnets and IPs will be removed.

Both operations are fully reversible through the audit log as long as you haven't purged snapshots.

## Snapshot Management

Go to **Configure > Snapshot Settings** (admin only) to:

- Set the maximum number of snapshots to keep (default: 20)
- Enable/disable automatic snapshots
- View snapshot statistics (count, total size, date range)
- Manually run cleanup to prune old snapshots

Snapshots are compressed and stored inside the database itself. They're typically very small — a database with hundreds of IPs compresses to a few KB per snapshot.

## Color Preferences

Each user can set their own terminal color scheme via **Configure > My Color Preference**. Options are green (default), cyan, yellow, and white. This is stored per-user so different people can have different colors on the same database.

## Tips

- `Esc` from anywhere returns to the main menu. Useful when you're several levels deep.
- The header bar always shows your current location as a breadcrumb trail (e.g., `Subnet Core-Servers (VLAN 100)`).
- Attribute inheritance saves a lot of typing. Set Customer and Location at the VLAN or subnet level, and only override at the IP level when something differs.
- The CIDR search is bidirectional — use it to find "everything in this /16" or "which /24 contains this /25."
- Exports only include attribute values that differ from inherited values, keeping spreadsheets clean.

## Moving to Production

When you're done experimenting:

```bash
rm tutorial.db
python ipam-tui.py production.db
```

Fresh database, clean slate. Set your database name, change the default admin password, create user accounts for your team, and start building your real data.
