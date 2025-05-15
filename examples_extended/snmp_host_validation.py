"""
Test Name: SNMP Trap Host Validation
Platform: cisco_ios
Tags: monitoring

Description:
This test ensures only the approved SNMP trap hosts are configured on a Cisco IOS device.

Expected trap hosts:
  - 192.168.10.1
  - 192.168.10.2

Any missing or extra SNMP hosts will result in a failure.
"""

import re

@high(
    name='snmp_host_validation',
    platform=['cisco_ios'],
)
def snmp_host_validation(configuration, commands, device):
    expected_hosts = {'192.168.10.1', '192.168.10.2'}

    # Run the CLI command to get SNMP hosts
    snmp_output = device.cli('show running-config | include snmp-server host')

    # Extract IPs from config lines
    configured_hosts = set(re.findall(r'snmp-server host (\d{1,3}(?:\.\d{1,3}){3})', snmp_output))

    # Compare actual with expected
    missing = expected_hosts - configured_hosts
    unexpected = configured_hosts - expected_hosts

    assert not missing, f"Missing expected SNMP hosts: {missing}"
    assert not unexpected, f"Unexpected SNMP hosts configured: {unexpected}"
