from comfy import high
import re


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

    # Extract version string like '6.6.2' or '7.0.1'
    match = re.search(r'Version\s+(\d+\.\d+\.\d+)', version_output)
    if not match:
        return  # Could not determine version, skip check

    version = match.group(1)
    major, minor, patch = map(int, version.split("."))

    def version_tuple_is_between(version_tuple, lower, upper):
        return lower < version_tuple < upper

    current = (major, minor, patch)

    vulnerable_ranges = [
        ((6, 1, 1), (6, 6, 4)),
        ((6, 6, 4), (6, 7, 2)),
        ((6, 7, 2), (7, 0, 2)),
        ((7, 0, 2), (7, 0, 12)),
        ((7, 0, 12), (7, 1, 1)),
        ((7, 1, 1), (7, 2, 1)),
    ]

    vulnerable = any(version_tuple_is_between(current, lower, upper) for (lower, upper) in vulnerable_ranges)

    if not vulnerable:
        return  # Not affected

    has_mpp = 'management-plane' in mpp_output
    has_snmp_restriction = all(feature in mpp_output for feature in ['inband', 'snmp'])

    # Only flag if both vulnerable version and MPP config match
    if vulnerable and has_mpp and has_snmp_restriction:
        assert False, (
            f"Device {device.name} is vulnerable to CVE-2021-1243. "
            "The device has management plane protection configured with SNMP restrictions, which could allow "
            "an unauthenticated attacker to bypass ACL restrictions for SNMP access. "
            "For more information, see "
            "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmp-7MKrW7Nq"
        )
