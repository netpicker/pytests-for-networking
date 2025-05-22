"""
CIS 1.3 - Disable all management related services on WAN port (Manual Check Automated)
Platform: fortinet
Level: 1

Description:
Checks that no insecure administrative access services (ping, http, https, ssh, snmp, radius-acct)
are enabled on WAN interfaces. This ensures management is not exposed via the WAN, reducing attack surface.

Expected: 'set allowaccess' on WAN ports should NOT include any of these services.

Reference: CIS Fortinet Benchmark v1.0.0 - Section 1.3
"""
from comfy import high
import re


@high(
    name='rule_cis_1_3_mgmt_services_disabled_on_wan',
    platform=['fortinet'],
    tags=['cis', 'networking'],
)
def rule_cis_1_3_mgmt_services_disabled_on_wan(configuration):
    # Define high-risk services
    forbidden_services = {'ping', 'https', 'http', 'ssh', 'snmp', 'radius-acct'}

    # Extract interface blocks
    blocks = configuration.split('edit ')
    violating_interfaces = []

    for block in blocks:
        lines = block.strip().splitlines()
        if not lines:
            continue

        iface = lines[0].strip('" ')
        # Adjust logic as needed based on naming conventions
        if not re.search(r'\bwan\b|port1', iface, re.IGNORECASE):
            continue

        for line in lines:
            if line.strip().startswith('set allowaccess'):
                services = set(line.strip().split()[2:])
                forbidden_used = forbidden_services & services
                if forbidden_used:
                    violating_interfaces.append((iface, sorted(forbidden_used)))

    assert not violating_interfaces, (
        "Management services enabled on WAN interfaces: " +
        ", ".join(f"{iface} → {services}" for iface, services in violating_interfaces)
    )
