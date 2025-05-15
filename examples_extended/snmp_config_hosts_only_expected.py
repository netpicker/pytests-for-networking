"""
Test Name: SNMP Trap Host Configuration Validation (Config-based)
Platforms: cisco_ios, cisco_xe, arista_eos

Description:
This test verifies that only the expected SNMP trap hosts are configured
on the device by scanning the full running configuration (not CLI commands).

Expected trap hosts:
  - 192.168.10.1
  - 192.168.10.2

The test will:
  ✅ Pass if the configured hosts exactly match the expected ones
  ❌ Fail if any expected host is missing
  ⚠️ Warn if any extra host is configured that shouldn't be

Example line from config:
    snmp-server host 192.168.10.1 version 2c public
"""
from comfy import high
import re


@high(
    name='snmp_config_hosts_only_expected',
    platform=['cisco_ios', 'arista_eos'],
)
def snmp_config_hosts_only_expected(configuration):
    expected_hosts = {'192.168.10.1', '192.168.10.2'}

    # Ensure we are working with raw config text
    config_text = str(configuration)

    # Find all IPs in snmp-server host lines
    configured_hosts = set(re.findall(
        r'^snmp-server host (\d{1,3}(?:\.\d{1,3}){3})',
        config_text,
        re.MULTILINE
    ))

    # Compare expected vs actual
    missing = expected_hosts - configured_hosts
    extra = configured_hosts - expected_hosts

    # Generate failure message if necessary
    messages = []
    if missing:
        messages.append(f"❌ Missing SNMP host(s): {sorted(missing)}")
    if extra:
        messages.append(f"⚠️ Unexpected SNMP host(s): {sorted(extra)}")

    if messages:
        raise AssertionError(" | ".join(messages))
