"""
Test Name: HA BGP Prefix Consistency
Platform: fortinet
Tags: fw_test

Description:
This test ensures that all BGP neighbors on a Fortinet firewall advertise
the same set of prefixes — useful in HA firewall pairs where consistency
between neighbors is required.

The test does the following:
  - Runs "get router info bgp summary" to get neighbor IPs
  - Fetches "received-routes" from each neighbor
  - Compares the received prefixes to ensure they are identical
"""

import re
from comfy import medium


@medium(
    name='rule_ha_bgp_prefix_consistency',
    platform=['fortinet'],
    device_tags='fw_test',
)
def rule_ha_bgp_prefix_consistency(configuration, commands, device):
    summary_output = device.cli("get router info bgp summary")
    neighbor_ips = []

    for line in summary_output.splitlines():
        match = re.match(r'\s*(\d{1,3}(?:\.\d{1,3}){3})\s+\d+', line)
        if match:
            neighbor_ips.append(match.group(1))

    assert len(neighbor_ips) >= 2, f"Expected at least 2 neighbors, found {len(neighbor_ips)}"

    neighbor_prefixes = {}

    for neighbor in neighbor_ips:
        received_output = device.cli(f"get router info bgp neighbors {neighbor} received-routes")
        prefixes = set()

        for line in received_output.splitlines():
            match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3}/\d+)', line)
            if match:
                prefixes.add(match.group(1))

        sorted_prefixes = sorted(prefixes)
        assert sorted_prefixes, f"No prefixes received from neighbor {neighbor}"
        neighbor_prefixes[neighbor] = sorted_prefixes

    reference_neighbor = neighbor_ips[0]
    reference_prefixes = neighbor_prefixes[reference_neighbor]

    for neighbor, prefixes in neighbor_prefixes.items():
        if prefixes != reference_prefixes:
            # Generate a manual diff string
            only_in_ref = sorted(set(reference_prefixes) - set(prefixes))
            only_in_neighbor = sorted(set(prefixes) - set(reference_prefixes))

            diff = []
            if only_in_ref:
                diff.append(f"\n❌ Missing from {neighbor}:\n  - " + "\n  - ".join(only_in_ref))
            if only_in_neighbor:
                diff.append(f"\n❌ Extra in {neighbor}:\n  - " + "\n  - ".join(only_in_neighbor))

            raise AssertionError(
                f"BGP prefix mismatch between {neighbor} and {reference_neighbor}."
                + "".join(diff)
            )
