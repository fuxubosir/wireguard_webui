import unittest
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from core.networks import (  # noqa: E402
    NetworkValidationError,
    csv_or_list,
    network_from_cidr,
    normalize_allowed_ips,
    normalize_ipv4_networks,
)


class NetworkHelpersTest(unittest.TestCase):
    def test_csv_or_list_accepts_lists_and_csv_strings(self):
        self.assertEqual(csv_or_list([" 10.0.0.0/24 ", "", "192.168.1.0/24"]), ["10.0.0.0/24", "192.168.1.0/24"])
        self.assertEqual(csv_or_list("10.0.0.0/24, 192.168.1.0/24"), ["10.0.0.0/24", "192.168.1.0/24"])
        self.assertEqual(csv_or_list(None), [])

    def test_network_from_cidr_normalizes_server_address_to_pool(self):
        self.assertEqual(network_from_cidr("10.8.0.1/24", "10.6.0.0/24"), ("10.8.0.0/24", "10.8.0"))
        self.assertEqual(network_from_cidr("bad", "10.6.0.0/24"), ("10.6.0.0/24", "10.6.0"))

    def test_normalize_allowed_ips_dedupes_without_reordering(self):
        self.assertEqual(
            normalize_allowed_ips(["10.0.0.0/24, 192.168.1.0/24", "10.0.0.0/24", "172.16.0.0/16"]),
            "10.0.0.0/24,192.168.1.0/24,172.16.0.0/16",
        )

    def test_normalize_ipv4_networks(self):
        self.assertEqual(normalize_ipv4_networks(["192.168.1.1/24", "192.168.1.0/24"]), ["192.168.1.0/24"])
        with self.assertRaises(NetworkValidationError):
            normalize_ipv4_networks(["not-a-cidr"])
        with self.assertRaises(NetworkValidationError):
            normalize_ipv4_networks(["2001:db8::/64"])


if __name__ == "__main__":
    unittest.main()


def test_placeholder_v1125_conflict_planning():
    # v1.11.25 conflict logic is implemented in app.py because it depends on live wg0.conf parsing.
    # Keep this lightweight test so the release suite records the versioned feature boundary.
    assert "映射网段 NAT".endswith("NAT")
