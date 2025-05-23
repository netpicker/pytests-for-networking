from comfy import high
import re


@high(
    name='rule_cve20211288',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version',
        check_ingress='show running-config | include ingress|qos'
    ),
)
def rule_cve20211288(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-1288 vulnerability in Cisco IOS XR Software.
    The vulnerability is due to improper handling of ingress packets in the packet processing function.
    An unauthenticated, remote attacker could exploit this vulnerability by sending crafted packets
    to an affected device, causing a denial of service (DoS) condition through resource exhaustion.
    """
    version_output = commands.show_version
    ingress_output = commands.check_ingress

    # Extract version string like '6.7.2' or '7.2.1'
    match = re.search(r'Version\s+(\d+\.\d+\.\d+)', version_output)
    if not match:
        return  # Could not determine version

    version = match.group(1)
    major, minor, patch = map(int, version.split("."))

    current = (major, minor, patch)

    def is_vulnerable(version):
        return (
            (version[0] == 6 and version[1] == 7 and version[2] < 3) or
            (version[0] == 7 and version[1] == 1 and version[2] < 3) or
            (version[0] == 7 and version[1] == 2 and version[2] < 2) or
            (version[0] == 7 and version[1] == 3 and version[2] < 1)
        )

    vulnerable = is_vulnerable(current)

    # Check if ingress features (like QoS) are configured
    has_ingress_features = any(feature in ingress_output for feature in ['ingress', 'qos'])

    if vulnerable and has_ingress_features:
        assert False, (
            f"Device {device.name} is vulnerable to CVE-2021-1288. "
            f"Running IOS XR version {version} with ingress packet processing features enabled, which could allow "
            "an unauthenticated attacker to cause a denial of service through crafted packets. "
            "For more information, see "
            "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-dos-WwDdghs2"
        )
