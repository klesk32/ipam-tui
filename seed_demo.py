#!/usr/bin/env python3
"""Seed a demo database from example_data.xlsx for Codespaces / local demos."""

import importlib.util
import os
import sys

DB_PATH = "demo.db"
XLSX_PATH = "example_data.xlsx"

# Remove stale DB so every Codespace starts fresh
if os.path.exists(DB_PATH):
    os.remove(DB_PATH)

# Load ipam-tui.py as a module
spec = importlib.util.spec_from_file_location("ipam", "./ipam-tui.py")
ipam = importlib.util.module_from_spec(spec)
sys.argv = ["seed_demo", DB_PATH]  # satisfy arg parsing
spec.loader.exec_module(ipam)

db = ipam.DB(DB_PATH)
db.init()

# Set admin as current user for audit log attribution
admin = db.get_user_by_username("admin")
db.set_current_user(admin)

# Set a display name
db.set_config("db_name", "Demo Environment")

# Import example data
if not os.path.exists(XLSX_PATH):
    print(f"Warning: {XLSX_PATH} not found — database will be empty.")
    print("Add example_data.xlsx to the repo root to populate the demo.")
else:
    added, updated, errors = ipam.import_from_xlsx(None, db, XLSX_PATH, "prefer_import", "")
    print(f"Imported: {added} added, {updated} updated, {len(errors)} errors")
    if errors:
        for e in errors[:5]:
            print(f"  {e}")

# Create a read-only demo account so visitors can browse without admin access
demo_pw = "DemoViewer2025!!"
db.create_user("demo", demo_pw, "viewer")
print(f"Demo database ready: {DB_PATH}")
print(f"  Admin login  — admin / admin")
print(f"  Viewer login — demo / {demo_pw}")
