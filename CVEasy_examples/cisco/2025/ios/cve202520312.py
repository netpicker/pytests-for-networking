from comfy import high


@high(
    name='rule_cve202520312',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_running_config='show running-config',
        show_snmp_community='show running-config | include snmp-server community',
        show_snmp_group='show running-config | include snmp-server group'
    ),
)
def rule_cve202520312(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20312 vulnerability in Cisco IOS XE Software.
    The vulnerability is in the SNMP subsystem and affects devices with WRED for MPLS EXP configured
    and SNMP enabled. An authenticated attacker can cause a DoS condition by sending a specific SNMP request.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if this is IOS XE Software (vulnerability only affects IOS XE)
    if 'IOS XE' not in version_output:
        return

    # Extract the running configuration
    config_output = commands.show_running_config

    # Check if WRED for MPLS EXP is configured
    # Look for 'random-detect mpls-exp-based' command under a policy-map
    wred_mpls_configured = 'random-detect mpls-exp-based' in config_output

    # If WRED for MPLS EXP is not configured, device is not vulnerable
    if not wred_mpls_configured:
        return

    # Check if the policy with WRED is actually applied to an interface
    # This is a simplified check - in reality we'd need to parse the policy-map name
    # and check if it's applied with 'service-policy'
    policy_applied = 'service-policy' in config_output

    if not policy_applied:
        return

    # Check if SNMP is enabled (any version)
    snmp_community_output = commands.show_snmp_community
    snmp_group_output = commands.show_snmp_group

    # SNMPv1/v2c is enabled if there are community strings
    snmpv1_v2c_enabled = bool(snmp_community_output.strip())

    # SNMPv3 is enabled if there are SNMP groups configured
    snmpv3_enabled = bool(snmp_group_output.strip())

    # SNMP is enabled if any version is configured
    snmp_enabled = snmpv1_v2c_enabled or snmpv3_enabled

    # Device is vulnerable if WRED for MPLS EXP is configured with applied policy AND SNMP is enabled
    is_vulnerable = wred_mpls_configured and policy_applied and snmp_enabled

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20312. "
        "The device is running Cisco IOS XE Software with WRED for MPLS EXP configured "
        "and SNMP enabled, which makes it susceptible to DoS attacks via malicious SNMP requests. "
        "An authenticated attacker can cause the device to reload unexpectedly. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmpwred-x3MJyf5M"
    )