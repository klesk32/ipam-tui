"""
Tests for IPAM TUI database layer.

Covers: CIDR overlap detection, subnet math, formatting, attribute inheritance,
        resolve cache, user auth, snapshot/restore, import/export round-trip.

Run with: pytest tests/test_db.py -v

Test version: 0.3.0
"""

import hashlib
import importlib
import ipaddress
import os
import sys
from pathlib import Path

import pytest

# Handle hyphenated filename: import ipam-tui.py as a module
_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_root))
ipam = importlib.import_module("ipam-tui")

DB = ipam.DB
User = ipam.User
is_non_routable = ipam.is_non_routable
is_rfc1918 = ipam.is_rfc1918
ranges_are_v6 = ipam.ranges_are_v6
fmt_addr_count = ipam.fmt_addr_count
fmt_utilization = ipam.fmt_utilization
compute_unallocated = ipam.compute_unallocated
ROLE_ADMIN = ipam.ROLE_ADMIN
ROLE_EDITOR = ipam.ROLE_EDITOR
ROLE_VIEWER = ipam.ROLE_VIEWER
STANDARD_KEYS = ipam.STANDARD_KEYS


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db():
    """Fresh in-memory DB with schema initialized and default admin logged in."""
    d = DB(":memory:")
    d.init()
    user = d.authenticate("admin", "admin")
    d.current_user = user
    return d


@pytest.fixture
def db_file(tmp_path):
    """Fresh DB backed by a temp file (needed for snapshot/restore tests)."""
    path = str(tmp_path / "test.db")
    d = DB(path)
    d.init()
    user = d.authenticate("admin", "admin")
    d.current_user = user
    return d


def _make_routed_vlan(db, vlan_num, name="Test"):
    return db.create_vlan(vlan_num, name, routed=1)


def _make_unrouted_vlan(db, vlan_num, name="Test"):
    return db.create_vlan(vlan_num, name, routed=0)


def _make_subnet_with_range(db, vlan_id, name, cidr):
    bd_id = db.create_subnet(vlan_id, name)
    db.add_subnet_range(bd_id, cidr)
    return bd_id


def _setup_ip_with_attrs(db, vlan_id, bd_id, ip_str, attrs=None):
    """Create an IP, link it to a subnet, and set attributes."""
    ip_id = db.ensure_ip(ip_str)
    db.set_ip_links(ip_id, vlan_id, bd_id)
    if attrs:
        for k, v in attrs.items():
            db.upsert_attr("ip", ip_id, k, v, 0)
    return ip_id


# ===========================================================================
# Overlap detection: check_routed_vlan_overlap
# ===========================================================================

class TestRoutedVlanOverlap:

    def test_v4_overlap_detected(self, db):
        v1 = _make_routed_vlan(db, 10)
        v2 = _make_routed_vlan(db, 20)
        _make_subnet_with_range(db, v1, "Net-A", "10.0.0.0/24")
        bd2 = db.create_subnet(v2, "Net-B")
        assert db.check_routed_vlan_overlap(bd2, "10.0.0.0/25") is not None

    def test_v4_no_overlap(self, db):
        v1 = _make_routed_vlan(db, 10)
        v2 = _make_routed_vlan(db, 20)
        _make_subnet_with_range(db, v1, "Net-A", "10.0.0.0/24")
        bd2 = db.create_subnet(v2, "Net-B")
        assert db.check_routed_vlan_overlap(bd2, "10.0.1.0/24") is None

    def test_v6_overlap_detected(self, db):
        v1 = _make_routed_vlan(db, 10)
        v2 = _make_routed_vlan(db, 20)
        _make_subnet_with_range(db, v1, "Net-A", "2001:db8:10::/48")
        bd2 = db.create_subnet(v2, "Net-B")
        assert db.check_routed_vlan_overlap(bd2, "2001:db8:10:1::/64") is not None

    def test_v6_no_overlap(self, db):
        v1 = _make_routed_vlan(db, 10)
        v2 = _make_routed_vlan(db, 20)
        _make_subnet_with_range(db, v1, "Net-A", "2001:db8:10::/48")
        bd2 = db.create_subnet(v2, "Net-B")
        assert db.check_routed_vlan_overlap(bd2, "2001:db8:20::/48") is None

    def test_cross_family_no_overlap(self, db):
        """v4 and v6 ranges can never overlap — must not raise TypeError."""
        v1 = _make_routed_vlan(db, 10)
        v2 = _make_routed_vlan(db, 20)
        _make_subnet_with_range(db, v1, "Net-v4", "10.0.0.0/24")
        bd2 = db.create_subnet(v2, "Net-v6")
        assert db.check_routed_vlan_overlap(bd2, "2001:db8:10::/64") is None

    def test_exact_duplicate_detected(self, db):
        v1 = _make_routed_vlan(db, 10)
        v2 = _make_routed_vlan(db, 20)
        _make_subnet_with_range(db, v1, "Net-A", "10.0.0.0/24")
        bd2 = db.create_subnet(v2, "Net-B")
        assert db.check_routed_vlan_overlap(bd2, "10.0.0.0/24") is not None

    def test_supernet_of_existing_detected(self, db):
        v1 = _make_routed_vlan(db, 10)
        v2 = _make_routed_vlan(db, 20)
        _make_subnet_with_range(db, v1, "Net-A", "10.0.0.0/25")
        bd2 = db.create_subnet(v2, "Net-B")
        assert db.check_routed_vlan_overlap(bd2, "10.0.0.0/24") is not None

    def test_subnet_of_existing_detected(self, db):
        v1 = _make_routed_vlan(db, 10)
        v2 = _make_routed_vlan(db, 20)
        _make_subnet_with_range(db, v1, "Net-A", "10.0.0.0/24")
        bd2 = db.create_subnet(v2, "Net-B")
        assert db.check_routed_vlan_overlap(bd2, "10.0.0.0/28") is not None


# ===========================================================================
# Overlap detection: check_vlan_can_be_routed
# ===========================================================================

class TestVlanCanBeRouted:

    def test_no_conflicts_allowed(self, db):
        v1 = _make_unrouted_vlan(db, 10)
        _make_subnet_with_range(db, v1, "Net-A", "10.0.0.0/24")
        assert db.check_vlan_can_be_routed(v1) is None

    def test_intra_vlan_overlap_rejected(self, db):
        v1 = _make_unrouted_vlan(db, 10)
        _make_subnet_with_range(db, v1, "Net-A", "10.0.0.0/24")
        _make_subnet_with_range(db, v1, "Net-B", "10.0.0.128/25")
        assert db.check_vlan_can_be_routed(v1) is not None

    def test_inter_vlan_overlap_rejected(self, db):
        v1 = _make_routed_vlan(db, 10)
        _make_subnet_with_range(db, v1, "Net-A", "10.0.0.0/24")
        v2 = _make_unrouted_vlan(db, 20)
        _make_subnet_with_range(db, v2, "Net-B", "10.0.0.0/25")
        assert db.check_vlan_can_be_routed(v2) is not None

    def test_cross_family_intra_vlan_allowed(self, db):
        v1 = _make_unrouted_vlan(db, 10)
        _make_subnet_with_range(db, v1, "Net-v4", "10.0.0.0/24")
        _make_subnet_with_range(db, v1, "Net-v6", "2001:db8:10::/64")
        assert db.check_vlan_can_be_routed(v1) is None

    def test_cross_family_inter_vlan_allowed(self, db):
        v1 = _make_routed_vlan(db, 10)
        _make_subnet_with_range(db, v1, "Net-v4", "10.0.0.0/24")
        v2 = _make_unrouted_vlan(db, 20)
        _make_subnet_with_range(db, v2, "Net-v6", "2001:db8:10::/64")
        assert db.check_vlan_can_be_routed(v2) is None


# ===========================================================================
# add_subnet_range validation
# ===========================================================================

class TestAddSubnetRange:

    def test_sibling_overlap_rejected(self, db):
        v1 = _make_routed_vlan(db, 10)
        bd_id = db.create_subnet(v1, "Net-A")
        db.add_subnet_range(bd_id, "10.0.0.0/24")
        with pytest.raises(ValueError, match="overlaps"):
            db.add_subnet_range(bd_id, "10.0.0.0/25")

    def test_cross_family_siblings_allowed(self, db):
        v1 = _make_routed_vlan(db, 10)
        bd_id = db.create_subnet(v1, "Dual-Stack")
        db.add_subnet_range(bd_id, "10.0.0.0/24")
        db.add_subnet_range(bd_id, "2001:db8:10::/64")
        assert len(db.list_subnet_ranges(bd_id)) == 2

    def test_routed_vlan_overlap_rejected(self, db):
        v1 = _make_routed_vlan(db, 10)
        v2 = _make_routed_vlan(db, 20)
        _make_subnet_with_range(db, v1, "Net-A", "10.0.0.0/24")
        bd2 = db.create_subnet(v2, "Net-B")
        with pytest.raises(ValueError, match="overlaps"):
            db.add_subnet_range(bd2, "10.0.0.128/25")

    def test_unrouted_vlan_overlap_allowed(self, db):
        v1 = _make_unrouted_vlan(db, 10)
        v2 = _make_unrouted_vlan(db, 20)
        _make_subnet_with_range(db, v1, "Net-A", "10.0.0.0/24")
        bd2 = db.create_subnet(v2, "Net-B")
        db.add_subnet_range(bd2, "10.0.0.0/24")
        assert len(db.list_subnet_ranges(bd2)) == 1

    def test_duplicate_range_returns_false(self, db):
        v1 = _make_routed_vlan(db, 10)
        bd_id = db.create_subnet(v1, "Net-A")
        assert db.add_subnet_range(bd_id, "10.0.0.0/24") is True
        assert db.add_subnet_range(bd_id, "10.0.0.0/24") is False

    def test_normalizes_cidr(self, db):
        v1 = _make_routed_vlan(db, 10)
        bd_id = db.create_subnet(v1, "Net-A")
        db.add_subnet_range(bd_id, "10.0.0.5/24")
        ranges = db.list_subnet_ranges(bd_id)
        assert ranges[0]["cidr"] == "10.0.0.0/24"


# ===========================================================================
# Owned subnet validation
# ===========================================================================

class TestOwnedSubnets:

    def test_rfc1918_rejected_v4(self, db):
        for cidr in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]:
            with pytest.raises(ValueError, match="RFC 1918"):
                db.create_owned_subnet(cidr, "Private")

    def test_ula_rejected_v6(self, db):
        with pytest.raises(ValueError, match="Non-routable"):
            db.create_owned_subnet("fd00::/48", "ULA")

    def test_link_local_rejected_v6(self, db):
        with pytest.raises(ValueError, match="Non-routable"):
            db.create_owned_subnet("fe80::/10", "Link-local")

    def test_multicast_rejected_v6(self, db):
        with pytest.raises(ValueError, match="Non-routable"):
            db.create_owned_subnet("ff00::/8", "Multicast")

    def test_public_v4_accepted(self, db):
        assert db.create_owned_subnet("203.0.113.0/24", "Public v4") > 0

    def test_public_v6_accepted(self, db):
        assert db.create_owned_subnet("2001:db8::/32", "Public v6") > 0

    def test_overlapping_owned_rejected(self, db):
        db.create_owned_subnet("203.0.113.0/24", "Block A")
        with pytest.raises(ValueError, match="Overlaps"):
            db.create_owned_subnet("203.0.113.0/25", "Block B")

    def test_cross_family_owned_allowed(self, db):
        db.create_owned_subnet("203.0.113.0/24", "v4 Block")
        db.create_owned_subnet("2001:db8::/32", "v6 Block")
        assert len(db.list_owned_subnets()) == 2


# ===========================================================================
# Utilization math
# ===========================================================================

class TestUtilization:

    def test_v4_utilization_counts(self, db):
        db.create_owned_subnet("203.0.113.0/24", "Test Block")
        v1 = _make_routed_vlan(db, 10)
        _make_subnet_with_range(db, v1, "Web", "203.0.113.0/27")
        _make_subnet_with_range(db, v1, "Mail", "203.0.113.32/27")
        util = db.get_all_owned_utilization()
        owned = db.list_owned_subnets()
        alloc, total = util[owned[0]["id"]]
        assert total == 256
        assert alloc == 64

    def test_v6_owned_ignores_v4_ranges(self, db):
        db.create_owned_subnet("2001:db8:800::/48", "v6 Block")
        v1 = _make_routed_vlan(db, 10)
        _make_subnet_with_range(db, v1, "v4-Net", "10.0.0.0/24")
        util = db.get_all_owned_utilization()
        owned = db.list_owned_subnets()
        alloc, _ = util[owned[0]["id"]]
        assert alloc == 0

    def test_v4_owned_ignores_v6_ranges(self, db):
        db.create_owned_subnet("203.0.113.0/24", "v4 Block")
        v1 = _make_routed_vlan(db, 10)
        _make_subnet_with_range(db, v1, "v6-Net", "2001:db8:10::/64")
        util = db.get_all_owned_utilization()
        owned = db.list_owned_subnets()
        alloc, _ = util[owned[0]["id"]]
        assert alloc == 0

    def test_mixed_db_counts_correctly(self, db):
        db.create_owned_subnet("203.0.113.0/24", "v4 Block")
        db.create_owned_subnet("2001:db8:800::/48", "v6 Block")
        v1 = _make_routed_vlan(db, 10)
        _make_subnet_with_range(db, v1, "v4-Web", "203.0.113.0/27")
        _make_subnet_with_range(db, v1, "v6-Web", "2001:db8:800:1::/64")

        util = db.get_all_owned_utilization()
        owned = {o["cidr"]: o["id"] for o in db.list_owned_subnets()}
        v4_alloc, v4_total = util[owned["203.0.113.0/24"]]
        assert v4_alloc == 32 and v4_total == 256
        v6_alloc, v6_total = util[owned["2001:db8:800::/48"]]
        assert v6_alloc == 2**64 and v6_total == 2**80

    def test_detail_allocations_cross_family(self, db):
        db.create_owned_subnet("203.0.113.0/24", "v4 Block")
        v1 = _make_routed_vlan(db, 10)
        _make_subnet_with_range(db, v1, "v6-Net", "2001:db8:10::/64")
        _make_subnet_with_range(db, v1, "v4-Net", "203.0.113.0/28")
        owned = db.list_owned_subnets()
        info = db.get_owned_subnet_allocations(owned[0]["id"])
        assert info is not None
        assert info["allocated_addrs"] == 16
        assert len(info["allocated"]) == 1


# ===========================================================================
# compute_unallocated
# ===========================================================================

class TestComputeUnallocated:

    def test_fully_unallocated(self):
        owned = ipaddress.ip_network("203.0.113.0/24")
        assert compute_unallocated(owned, []) == [owned]

    def test_partial_allocation(self):
        owned = ipaddress.ip_network("203.0.113.0/24")
        alloc = [ipaddress.ip_network("203.0.113.0/25")]
        result = compute_unallocated(owned, alloc)
        assert ipaddress.ip_network("203.0.113.128/25") in result
        assert sum(n.num_addresses for n in result) == 128

    def test_fully_allocated(self):
        owned = ipaddress.ip_network("203.0.113.0/24")
        assert compute_unallocated(owned, [owned]) == []

    def test_multiple_allocations(self):
        owned = ipaddress.ip_network("203.0.113.0/24")
        alloc = [
            ipaddress.ip_network("203.0.113.0/26"),
            ipaddress.ip_network("203.0.113.128/26"),
        ]
        assert sum(n.num_addresses for n in compute_unallocated(owned, alloc)) == 128


# ===========================================================================
# is_non_routable / is_rfc1918
# ===========================================================================

class TestNonRoutable:

    def test_rfc1918_v4(self):
        assert is_non_routable("10.0.0.0/8") is True
        assert is_non_routable("172.16.0.0/12") is True
        assert is_non_routable("192.168.1.0/24") is True

    def test_public_v4(self):
        assert is_non_routable("203.0.113.0/24") is False
        assert is_non_routable("8.8.8.0/24") is False

    def test_ula_v6(self):
        assert is_non_routable("fd00::/48") is True
        assert is_non_routable("fc00::/7") is True

    def test_link_local_v6(self):
        assert is_non_routable("fe80::/10") is True
        assert is_non_routable("fe80::1/128") is True

    def test_multicast_v6(self):
        assert is_non_routable("ff00::/8") is True
        assert is_non_routable("ff02::1/128") is True

    def test_loopback_v6(self):
        assert is_non_routable("::1/128") is True

    def test_public_v6(self):
        assert is_non_routable("2001:db8::/32") is False
        assert is_non_routable("2600::/48") is False

    def test_is_rfc1918_only_v4(self):
        assert is_rfc1918("10.0.0.0/8") is True
        assert is_rfc1918("203.0.113.0/24") is False


# ===========================================================================
# ranges_are_v6
# ===========================================================================

class TestRangesAreV6:

    def test_v4_only(self):
        assert ranges_are_v6([{"cidr": "10.0.0.0/24"}, {"cidr": "172.16.0.0/16"}]) is False

    def test_v6_only(self):
        assert ranges_are_v6([{"cidr": "2001:db8::/32"}]) is True

    def test_mixed(self):
        assert ranges_are_v6([{"cidr": "10.0.0.0/24"}, {"cidr": "2001:db8::/64"}]) is True

    def test_empty(self):
        assert ranges_are_v6([]) is False


# ===========================================================================
# Formatting: fmt_addr_count, fmt_utilization
# ===========================================================================

class TestFormatting:

    def test_small_count(self):
        assert fmt_addr_count(256) == "256"
        assert fmt_addr_count(65536) == "65,536"

    def test_power_of_two(self):
        assert fmt_addr_count(2**64) == "2^64"
        assert fmt_addr_count(2**80) == "2^80"
        assert fmt_addr_count(2**128) == "2^128"

    def test_non_power_large(self):
        assert fmt_addr_count(2**64 + 1).startswith("~2^")

    def test_v4_utilization(self):
        result = fmt_utilization(120, 256)
        assert "120" in result and "256" in result and "46.9%" in result

    def test_v6_utilization_compact(self):
        result = fmt_utilization(5, 2**80)
        assert "2^80" in result
        assert "0.0%" in result
        assert "1208925819614629174706176" not in result

    def test_small_v6_subnet_normal_format(self):
        result = fmt_utilization(2, 4)
        assert "2" in result and "4" in result and "50.0%" in result

    def test_zero_total(self):
        assert "0.0%" in fmt_utilization(0, 0)


# ===========================================================================
# Attribute inheritance
# ===========================================================================

class TestAttributeInheritance:

    def test_subnet_attr_inherited_by_ip(self, db):
        """Attribute set on subnet should appear in effective attrs for an IP."""
        v1 = _make_routed_vlan(db, 10)
        bd_id = _make_subnet_with_range(db, v1, "Net-A", "10.0.0.0/24")
        db.upsert_attr("bd", bd_id, "Customer", "Acme Corp", 1)
        _setup_ip_with_attrs(db, v1, bd_id, "10.0.0.1")
        _, eff = db.effective_attrs_for_ip("10.0.0.1")
        assert eff["Customer"] == "Acme Corp"

    def test_ip_attr_overrides_subnet(self, db):
        """Attribute on IP should override subnet value."""
        v1 = _make_routed_vlan(db, 10)
        bd_id = _make_subnet_with_range(db, v1, "Net-A", "10.0.0.0/24")
        db.upsert_attr("bd", bd_id, "Customer", "Widgets Inc", 1)
        _setup_ip_with_attrs(db, v1, bd_id, "10.0.0.1", {"Customer": "Globex"})
        _, eff = db.effective_attrs_for_ip("10.0.0.1")
        assert eff["Customer"] == "Globex"

    def test_clearing_ip_attr_restores_inherited(self, db):
        """Deleting an IP-level attr should let the parent value show through."""
        v1 = _make_routed_vlan(db, 10)
        bd_id = _make_subnet_with_range(db, v1, "Net-A", "10.0.0.0/24")
        db.upsert_attr("bd", bd_id, "Customer", "Acme Corp", 1)
        ip_id = _setup_ip_with_attrs(db, v1, bd_id, "10.0.0.1", {"Customer": "Override"})
        _, eff = db.effective_attrs_for_ip("10.0.0.1")
        assert eff["Customer"] == "Override"
        db.delete_attr("ip", ip_id, "Customer")
        _, eff = db.effective_attrs_for_ip("10.0.0.1")
        assert eff["Customer"] == "Acme Corp"

    def test_empty_ip_attr_does_not_override(self, db):
        """An empty string IP attribute should not mask a parent value."""
        v1 = _make_routed_vlan(db, 10)
        bd_id = _make_subnet_with_range(db, v1, "Net-A", "10.0.0.0/24")
        db.upsert_attr("bd", bd_id, "Location", "DC-East-1", 1)
        _setup_ip_with_attrs(db, v1, bd_id, "10.0.0.1", {"Location": ""})
        _, eff = db.effective_attrs_for_ip("10.0.0.1")
        assert eff["Location"] == "DC-East-1"

    def test_multiple_ips_different_overrides(self, db):
        """Two IPs in the same subnet can have different overrides."""
        v1 = _make_routed_vlan(db, 10)
        bd_id = _make_subnet_with_range(db, v1, "Net-A", "10.0.0.0/24")
        db.upsert_attr("bd", bd_id, "Customer", "Default Co", 1)
        _setup_ip_with_attrs(db, v1, bd_id, "10.0.0.1", {"Customer": "Alpha"})
        _setup_ip_with_attrs(db, v1, bd_id, "10.0.0.2", {"Customer": "Beta"})
        _setup_ip_with_attrs(db, v1, bd_id, "10.0.0.3")
        _, eff1 = db.effective_attrs_for_ip("10.0.0.1")
        _, eff2 = db.effective_attrs_for_ip("10.0.0.2")
        _, eff3 = db.effective_attrs_for_ip("10.0.0.3")
        assert eff1["Customer"] == "Alpha"
        assert eff2["Customer"] == "Beta"
        assert eff3["Customer"] == "Default Co"

    def test_subnet_overrides_vlan_for_shared_keys(self, db):
        """Subnet attr should override VLAN attr for the same key."""
        v1 = _make_routed_vlan(db, 10)
        bd_id = _make_subnet_with_range(db, v1, "Net-A", "10.0.0.0/24")
        db.upsert_attr("vlan", v1, "Customer", "VLAN-Level", 1)
        # Subnet has no explicit Customer — VLAN value should propagate
        _setup_ip_with_attrs(db, v1, bd_id, "10.0.0.1")
        _, eff = db.effective_attrs_for_ip("10.0.0.1")
        assert eff["Customer"] == "VLAN-Level"

        # Now set Customer on subnet — should override
        db.upsert_attr("bd", bd_id, "Customer", "Subnet-Level", 1)
        _, eff = db.effective_attrs_for_ip("10.0.0.1")
        assert eff["Customer"] == "Subnet-Level"

    def test_vlan_customer_propagates_to_ip(self, db):
        """VLAN-level Customer should propagate to IPs when subnet has no override."""
        v1 = _make_routed_vlan(db, 10)
        bd_id = _make_subnet_with_range(db, v1, "Net-A", "10.0.0.0/24")
        db.upsert_attr("vlan", v1, "Customer", "VLAN-Cust", 1)
        db.upsert_attr("vlan", v1, "Location", "VLAN-Loc", 1)
        _setup_ip_with_attrs(db, v1, bd_id, "10.0.0.1")
        _, eff = db.effective_attrs_for_ip("10.0.0.1")
        assert eff["Customer"] == "VLAN-Cust"
        assert eff["Location"] == "VLAN-Loc"

    def test_vlan_only_attrs_propagate(self, db):
        """VLAN attrs for keys NOT in VLAN_SUBNET_KEYS should propagate through.

        get_attrs("bd", ...) only defaults VLAN_SUBNET_KEYS (Customer, Location,
        Comment), so other keys like Asset pass through from VLAN to IP."""
        v1 = _make_routed_vlan(db, 10)
        bd_id = _make_subnet_with_range(db, v1, "Net-A", "10.0.0.0/24")
        db.upsert_attr("vlan", v1, "Asset", "VLAN-Asset", 1)
        _setup_ip_with_attrs(db, v1, bd_id, "10.0.0.1")
        _, inherited = db.inherited_attrs_for_ip("10.0.0.1")
        assert inherited.get("Asset") == "VLAN-Asset"

    def test_direct_attr_scope_access(self, db):
        """get_attrs at each scope level should return only that scope's values."""
        v1 = _make_routed_vlan(db, 10)
        bd_id = _make_subnet_with_range(db, v1, "Net-A", "10.0.0.0/24")
        db.upsert_attr("vlan", v1, "Customer", "VLAN-Cust", 1)
        db.upsert_attr("bd", bd_id, "Location", "BD-Loc", 1)
        ip_id = _setup_ip_with_attrs(db, v1, bd_id, "10.0.0.1", {"Comment": "IP-Comment"})

        vlan_attrs = db.get_attrs("vlan", v1)
        assert vlan_attrs["Customer"] == "VLAN-Cust"

        bd_attrs = db.get_attrs("bd", bd_id)
        assert bd_attrs["Location"] == "BD-Loc"
        assert bd_attrs["Customer"] == ""  # Not inherited from VLAN

        ip_attrs = db.get_attrs("ip", ip_id)
        assert ip_attrs["Comment"] == "IP-Comment"
        assert ip_attrs["Customer"] == ""  # Not inherited from subnet


# ===========================================================================
# Resolve cache (resolve_for_ip)
# ===========================================================================

class TestResolveForIp:

    def test_v4_resolves_to_correct_subnet(self, db):
        v1 = _make_routed_vlan(db, 10, "Mgmt")
        bd1 = _make_subnet_with_range(db, v1, "Servers", "10.0.0.0/24")
        bd2 = _make_subnet_with_range(db, v1, "Printers", "10.0.1.0/24")
        res = db.resolve_for_ip("10.0.0.50")
        assert res.bd_id == bd1 and res.bd_name == "Servers"
        res = db.resolve_for_ip("10.0.1.50")
        assert res.bd_id == bd2 and res.bd_name == "Printers"

    def test_v6_resolves(self, db):
        v1 = _make_routed_vlan(db, 10, "Core")
        bd1 = _make_subnet_with_range(db, v1, "v6-Net", "2001:db8:10::/64")
        res = db.resolve_for_ip("2001:db8:10::cafe")
        assert res.bd_id == bd1 and res.vlan_num == 10

    def test_unknown_ip_returns_empty(self, db):
        _make_routed_vlan(db, 10)
        res = db.resolve_for_ip("192.168.99.1")
        assert res.vlan_id is None and res.bd_id is None

    def test_most_specific_match_wins(self, db):
        """When an IP falls in multiple ranges, the longest prefix should win."""
        v1 = _make_unrouted_vlan(db, 10)
        v2 = _make_routed_vlan(db, 20)
        bd_wide = _make_subnet_with_range(db, v1, "Wide", "10.0.0.0/16")
        bd_narrow = _make_subnet_with_range(db, v2, "Narrow", "10.0.1.0/24")
        res = db.resolve_for_ip("10.0.1.50")
        assert res.bd_id == bd_narrow and res.bd_name == "Narrow"

    def test_cache_invalidation_after_new_range(self, db):
        """Adding a range should invalidate the cache so new lookups find it."""
        v1 = _make_routed_vlan(db, 10)
        _make_subnet_with_range(db, v1, "Net-A", "10.0.0.0/24")
        # Prime cache
        assert db.resolve_for_ip("10.0.1.1").bd_id is None
        # Add new range — cache should be invalidated
        bd2 = _make_subnet_with_range(db, v1, "Net-B", "10.0.1.0/24")
        assert db.resolve_for_ip("10.0.1.1").bd_id == bd2

    def test_cross_family_resolve(self, db):
        """v4 IP should not match v6 range and vice versa."""
        v1 = _make_routed_vlan(db, 10)
        _make_subnet_with_range(db, v1, "v6-Only", "2001:db8:10::/64")
        assert db.resolve_for_ip("10.0.0.1").bd_id is None


# ===========================================================================
# User authentication and management
# ===========================================================================

class TestUserAuth:

    def test_default_admin_login(self, db):
        user = db.authenticate("admin", "admin")
        assert user is not None and user.role == ROLE_ADMIN

    def test_wrong_password_rejected(self, db):
        assert db.authenticate("admin", "wrongpassword") is None

    def test_nonexistent_user_rejected(self, db):
        assert db.authenticate("nosuchuser", "admin") is None

    def test_create_and_authenticate(self, db):
        db.create_user("editor1", "EditorPass123!@#$", ROLE_EDITOR)
        user = db.authenticate("editor1", "EditorPass123!@#$")
        assert user is not None and user.role == ROLE_EDITOR

    def test_password_change(self, db):
        db.create_user("testuser", "OldPass123!@#$%^&", ROLE_VIEWER)
        user = db.authenticate("testuser", "OldPass123!@#$%^&")
        db.update_user_password(user.id, "NewPass456!@#$%^&")
        assert db.authenticate("testuser", "OldPass123!@#$%^&") is None
        assert db.authenticate("testuser", "NewPass456!@#$%^&") is not None

    def test_role_update(self, db):
        db.create_user("promoted", "TestPass123!@#$%^", ROLE_VIEWER)
        user = db.authenticate("promoted", "TestPass123!@#$%^")
        db.update_user_role(user.id, ROLE_ADMIN)
        assert db.get_user_by_id(user.id).role == ROLE_ADMIN

    def test_delete_user(self, db):
        db.create_user("temp", "TempPass123!@#$%^", ROLE_VIEWER)
        user = db.get_user_by_username("temp")
        db.delete_user(user.id)
        assert db.get_user_by_username("temp") is None

    def test_count_admins(self, db):
        assert db.count_admins() == 1
        db.create_user("admin2", "Admin2Pass!@#$%^&", ROLE_ADMIN)
        assert db.count_admins() == 2

    def test_user_roles_permissions(self, db):
        db.create_user("v", "ViewerPass!@#$%^&*", ROLE_VIEWER)
        db.create_user("e", "EditorPass!@#$%^&*", ROLE_EDITOR)
        db.create_user("a", "AdminPass2!@#$%^&*", ROLE_ADMIN)
        viewer = db.authenticate("v", "ViewerPass!@#$%^&*")
        editor = db.authenticate("e", "EditorPass!@#$%^&*")
        admin = db.authenticate("a", "AdminPass2!@#$%^&*")
        assert viewer.is_viewer() and not viewer.can_edit() and not viewer.is_admin()
        assert not editor.is_viewer() and editor.can_edit() and not editor.is_admin()
        assert not admin.is_viewer() and admin.can_edit() and admin.is_admin()

    def test_legacy_sha256_upgrade(self, db):
        """Legacy SHA-256 hashes should authenticate and auto-upgrade to PBKDF2."""
        legacy_hash = hashlib.sha256("legacypass".encode()).hexdigest()
        db.x(
            "INSERT INTO users(username, password_hash, role, fg_color) VALUES(?,?,?,?)",
            ("legacy_user", legacy_hash, ROLE_VIEWER, "green")
        )
        user = db.authenticate("legacy_user", "legacypass")
        assert user is not None
        # Hash should now contain ':' (PBKDF2 salt:hash format)
        rows = db.q("SELECT password_hash FROM users WHERE username='legacy_user'")
        assert ':' in rows[0]["password_hash"]
        # Should still work after upgrade
        assert db.authenticate("legacy_user", "legacypass") is not None


# ===========================================================================
# Snapshot / Restore
# ===========================================================================

class TestSnapshotRestore:

    def test_create_snapshot(self, db):
        assert db.create_snapshot() > 0

    def test_restore_reverts_data(self, db_file):
        v1 = _make_routed_vlan(db_file, 10, "Original")
        _make_subnet_with_range(db_file, v1, "Net-A", "10.0.0.0/24")
        snap_id = db_file.create_snapshot()

        _make_routed_vlan(db_file, 20, "AfterSnapshot")
        assert any(v["name"] == "AfterSnapshot" for v in db_file.list_vlans())

        db_path = db_file.con.execute("PRAGMA database_list").fetchone()[2]
        db_file.restore_snapshot(snap_id, db_path)

        vlans = db_file.list_vlans()
        assert not any(v["name"] == "AfterSnapshot" for v in vlans)
        assert any(v["name"] == "Original" for v in vlans)

    def test_restore_preserves_audit_log(self, db_file):
        _make_routed_vlan(db_file, 10, "V10")
        snap_id = db_file.create_snapshot()
        _make_routed_vlan(db_file, 20, "V20")
        count_before = len(db_file.list_audit_log())

        db_path = db_file.con.execute("PRAGMA database_list").fetchone()[2]
        db_file.restore_snapshot(snap_id, db_path)

        assert len(db_file.list_audit_log()) >= count_before

    def test_restore_creates_backup_file(self, db_file):
        _make_routed_vlan(db_file, 10)
        snap_id = db_file.create_snapshot()
        db_path = db_file.con.execute("PRAGMA database_list").fetchone()[2]
        backup_file = db_file.restore_snapshot(snap_id, db_path)
        assert os.path.exists(backup_file)
        assert ".backup_" in backup_file


# ===========================================================================
# Import / Export round-trip
# ===========================================================================

class TestImportExport:

    @pytest.fixture(autouse=True)
    def check_openpyxl(self):
        pytest.importorskip("openpyxl")

    def test_round_trip_preserves_vlans(self, db, tmp_path):
        export_fn = ipam.export_vlans_to_xlsx
        import_fn = ipam.import_from_xlsx

        v1 = _make_routed_vlan(db, 10, "Mgmt")
        bd1 = _make_subnet_with_range(db, v1, "Servers", "10.0.0.0/24")
        _setup_ip_with_attrs(db, v1, bd1, "10.0.0.1", {"Customer": "Acme", "Location": "DC-1"})
        _setup_ip_with_attrs(db, v1, bd1, "10.0.0.2", {"Customer": "Beta", "Asset": "Dell R740"})

        v2 = _make_routed_vlan(db, 20, "Web")
        bd2 = _make_subnet_with_range(db, v2, "Frontend", "10.20.0.0/24")
        _setup_ip_with_attrs(db, v2, bd2, "10.20.0.1", {"Customer": "Acme", "Comment": "Gateway"})

        xlsx_path = str(tmp_path / "export_test.xlsx")
        export_fn(db, None, xlsx_path)
        assert os.path.exists(xlsx_path)

        db2 = DB(":memory:")
        db2.init()
        db2.current_user = db2.authenticate("admin", "admin")
        added, updated, errors = import_fn(None, db2, xlsx_path, "prefer_import", "")

        vlan_nums = {v["vlan_num"] for v in db2.list_vlans()}
        assert 10 in vlan_nums and 20 in vlan_nums

        v10 = db2.get_vlan_by_num(10)
        assert v10["name"] == "Mgmt" and v10["routed"] == 1

        subnets = db2.list_subnets(v10["id"])
        assert len(subnets) == 1 and subnets[0]["name"] == "Servers"

        ip_row = db2.get_ip_row("10.0.0.1")
        assert ip_row is not None
        attrs = db2.get_attrs("ip", ip_row["id"])
        assert attrs["Customer"] == "Acme" and attrs["Location"] == "DC-1"

    def test_round_trip_preserves_v6(self, db, tmp_path):
        export_fn = ipam.export_vlans_to_xlsx
        import_fn = ipam.import_from_xlsx

        v1 = _make_routed_vlan(db, 10, "DualStack")
        bd1 = _make_subnet_with_range(db, v1, "v4", "10.0.0.0/24")
        bd2 = _make_subnet_with_range(db, v1, "v6", "2001:db8:10::/64")
        _setup_ip_with_attrs(db, v1, bd1, "10.0.0.1", {"Customer": "v4-host"})
        _setup_ip_with_attrs(db, v1, bd2, "2001:db8:10::1", {"Customer": "v6-host"})

        xlsx_path = str(tmp_path / "v6_test.xlsx")
        export_fn(db, None, xlsx_path)

        db2 = DB(":memory:")
        db2.init()
        db2.current_user = db2.authenticate("admin", "admin")
        import_fn(None, db2, xlsx_path, "prefer_import", "")

        assert db2.get_ip_row("10.0.0.1") is not None
        v6_row = db2.get_ip_row("2001:db8:10::1")
        assert v6_row is not None
        assert db2.get_attrs("ip", v6_row["id"])["Customer"] == "v6-host"

    def test_round_trip_preserves_owned_subnets(self, db, tmp_path):
        export_fn = ipam.export_vlans_to_xlsx
        import_fn = ipam.import_from_xlsx

        db.create_owned_subnet("203.0.113.0/24", "Cogent Block")
        db.create_owned_subnet("2001:db8:800::/48", "v6 Allocation")
        _make_routed_vlan(db, 10, "Placeholder")

        xlsx_path = str(tmp_path / "owned_test.xlsx")
        export_fn(db, None, xlsx_path)

        db2 = DB(":memory:")
        db2.init()
        db2.current_user = db2.authenticate("admin", "admin")
        import_fn(None, db2, xlsx_path, "prefer_import", "")

        cidrs = {o["cidr"] for o in db2.list_owned_subnets()}
        assert "203.0.113.0/24" in cidrs and "2001:db8:800::/48" in cidrs

    def test_import_no_errors_on_clean_data(self, db, tmp_path):
        export_fn = ipam.export_vlans_to_xlsx
        import_fn = ipam.import_from_xlsx

        v1 = _make_routed_vlan(db, 10, "Clean")
        bd1 = _make_subnet_with_range(db, v1, "Net", "10.0.0.0/24")
        _setup_ip_with_attrs(db, v1, bd1, "10.0.0.1", {"Customer": "Test"})

        xlsx_path = str(tmp_path / "clean_test.xlsx")
        export_fn(db, None, xlsx_path)

        db2 = DB(":memory:")
        db2.init()
        db2.current_user = db2.authenticate("admin", "admin")
        added, updated, errors = import_fn(None, db2, xlsx_path, "prefer_import", "")
        assert len(errors) == 0 and added > 0


# ===========================================================================
# Audit log
# ===========================================================================

class TestAuditLog:

    def test_actions_are_logged(self, db):
        _make_routed_vlan(db, 10, "Logged")
        log = db.list_audit_log()
        assert any("VLAN" in e["description"] for e in log)

    def test_logged_by_tracks_user(self, db):
        _make_routed_vlan(db, 10)
        log = db.list_audit_log()
        assert any(e["logged_by"] == "admin" for e in log)

    def test_snapshot_linked_to_destructive_ops(self, db):
        v1 = _make_routed_vlan(db, 10, "ToDelete")
        bd1 = _make_subnet_with_range(db, v1, "Net", "10.0.0.0/24")
        db.delete_subnet(bd1)
        log = db.list_audit_log()
        delete_entries = [e for e in log if "delete" in e["action"].lower() and "subnet" in e["action"].lower()]
        assert len(delete_entries) > 0
        assert any(e["snapshot_id"] is not None for e in delete_entries)
