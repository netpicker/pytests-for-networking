from comfy import high


@high(
    name='rule_cve20211243',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version',
        check_mpp='show running-config | include control-plane|management-plane|snmp|inband'
    ),
)
def rule_cve20211243(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-1243 vulnerability in Cisco IOS XR Software.
    The vulnerability is due to incorrect LPTS programming when using SNMP with management plane protection.
    An unauthenticated, remote attacker could exploit this vulnerability by connecting to an affected
    device using SNMP, allowing connections despite the management plane protection that is configured
    to deny access to the SNMP server.
    Note: Valid credentials are still required to execute any SNMP requests.
    """
    # Extract the output of the commands
    version_output = commands.show_version
    mpp_output = commands.check_mpp

    # Check if management plane protection is configured with SNMP restrictions
    has_mpp = 'management-plane' in mpp_output
    has_snmp_restriction = all(feature in mpp_output for feature in [
        'inband',
        'snmp'
    ])

    # If MPP is not configured or SNMP is not restricted, device is not vulnerable
    if not (has_mpp and has_snmp_restriction):
        return

    # Assert that the device is not vulnerable
    assert not (has_mpp and has_snmp_restriction), (
        f"Device {device.name} is vulnerable to CVE-2021-1243. "
        "The device has management plane protection configured with SNMP restrictions, which could allow "
        "an unauthenticated attacker to bypass ACL restrictions for SNMP access. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmp-7MKrW7Nq"
    )
