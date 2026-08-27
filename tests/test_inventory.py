from __future__ import annotations

from pathlib import Path

import pytest

from convoy.errors import InventoryError
from convoy.inventory import Host, Inventory, Role


def test_lookup_and_role_filter(inventory: Inventory) -> None:
    assert inventory.host("mgmt-01").role is Role.MANAGEMENT
    gateways = inventory.hosts_by_role(Role.GATEWAY)
    assert [h.name for h in gateways] == ["fw-01"]


def test_missing_host_raises(inventory: Inventory) -> None:
    with pytest.raises(InventoryError):
        inventory.host("nope")


def test_example_inventory_loads() -> None:
    """The committed example inventory must always be valid."""
    example = Path(__file__).resolve().parents[1] / "examples" / "inventory.example.yaml"
    inv = Inventory.load(example)
    assert inv.hosts_by_role(Role.MANAGEMENT)
    assert any(s.clusters for s in inv.sites)


# -- Host field validation (security) ---------------------------------------------
#
# ``address`` is the only field binding an inventory row to a specific real
# device: SSH connections, stored-credential handoffs, and the Management API
# target-identity check all rest on it. It was previously an unconstrained
# ``str``, which let a row be pointed anywhere. See inventory.Host.


@pytest.mark.parametrize(
    "address",
    ["10.0.0.1", "192.0.2.20", "fw-core-prod", "mgmt01.example.internal", "2001:db8::1", "host."],
)
def test_host_accepts_real_addresses(address: str) -> None:
    assert Host(name="x", address=address, role=Role.GATEWAY).address == address


@pytest.mark.parametrize(
    "address",
    [
        "",
        "   ",
        "http://attacker.example.net",
        "attacker.example.net:22",
        "1.2.3.4 ; rm -rf /",
        "two words",
        "user@host",
        "-leading-hyphen.example.com",
        "a" * 300,
    ],
)
def test_host_rejects_malformed_addresses(address: str) -> None:
    with pytest.raises(ValueError):
        Host(name="x", address=address, role=Role.GATEWAY)


@pytest.mark.parametrize("port", [0, -1, 65536, 999999])
def test_host_rejects_out_of_range_ssh_port(port: int) -> None:
    with pytest.raises(ValueError):
        Host(name="x", address="10.0.0.1", role=Role.GATEWAY, ssh_port=port)


def test_host_rejects_empty_name() -> None:
    with pytest.raises(ValueError):
        Host(name="   ", address="10.0.0.1", role=Role.GATEWAY)


def test_host_strips_surrounding_whitespace() -> None:
    host = Host(name="  fw-01  ", address="  10.0.0.1  ", role=Role.GATEWAY, ssh_user="  admin  ")
    assert (host.name, host.address, host.ssh_user) == ("fw-01", "10.0.0.1", "admin")
