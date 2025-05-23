from comfy import high
import re


@high(
    name='rule_cve20211313',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version',
        check_enf='show running-config | include enf|enforcement'
    ),
)
def rule_cve20211313(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-1313 vulnerability in Cisco IOS XR Software.
    The vulnerability is due to improper handling of ingress packets in the enforcement broker
    function. An unauthenticated, remote attacker could exploit this vulnerability by sending
    crafted packets to an affected device, causing a denial of service (DoS) condition through
    resource exhaustion.
    """
    version_output = commands.show_version
    enf_output = commands.check_enf

    # Extract version string like '6.7.2' or '7.2.1'
    match = re.search(r'Version\s+(\d+\.\d+\.\d+)', version_output)
    if not match:
        return  # Could not determine version

    version = match.group(1)
    major, minor, patch = map(int, version.split("."))
    current = (major, minor, patch)

    def is_vulnerable(version):
        # Version < 5.2.6
        if version[0] == 5 and version[1] == 0:
            return True
        if version[0] == 5 and version[1] == 2 and version[2] < 6:
            return True
        if version[0] == 5 and version[1] == 3 and version[2] < 4:
            return True
        if version[0] == 6 and version[1] == 0 and version[2] < 2:
            return True
        if version[0] < 5:
            return True
        return False

    vulnerable = is_vulnerable(current)

    # Check if enforcement features are configured
    has_enf_features = any(feature in enf_output for feature in ['enf', 'enforcement'])

    if vulnerable and has_enf_features:
        assert False, (
            f"Device {device.name} is vulnerable to CVE-2021-1313. "
            f"Running IOS XR version {version} with enforcement broker features enabled, which could allow "
            "an unauthenticated attacker to cause a denial of service through crafted packets. "
            "For more information, see "
            "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-dos-WwDdghs2"
        )
