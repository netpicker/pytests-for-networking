from comfy import high
import re


@high(
    name='rule_cve20211440',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version',
        check_rpki='show running-config | include router bgp|rpki'
    ),
)
def rule_cve20211440(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-1440 vulnerability in Cisco IOS XR Software.
    The vulnerability is due to incorrect handling of specific RPKI to Router (RTR) Protocol
    packet headers. An unauthenticated, remote attacker could exploit this vulnerability by
    compromising the RPKI validator server or using man-in-the-middle techniques to send crafted
    RTR packets, causing the BGP process to crash and resulting in a denial of service condition.
    """
    version_output = commands.show_version
    rpki_output = commands.check_rpki

    # Extract version string like '6.6.2'
    match = re.search(r'Version\s+(\d+\.\d+\.\d+)', version_output)
    if not match:
        return  # Could not determine version

    version = match.group(1)
    major, minor, patch = map(int, version.split("."))

    current = (major, minor, patch)

    def is_vulnerable(version):
        # Assume any version before 7.3.1 is vulnerable
        if version[0] == 7 and version[1] == 3 and version[2] < 15:
            return True
        if version[0] == 7 and version[1] == 4 and version[2] < 1:
            return True
        if version[0] < 7:
            return True
        return False

    vulnerable = is_vulnerable(current)

    # Check if BGP is configured with RPKI
    has_bgp = 'router bgp' in rpki_output
    has_rpki = 'rpki' in rpki_output

    if vulnerable and has_bgp and has_rpki:
        assert False, (
            f"Device {device.name} is vulnerable to CVE-2021-1440. "
            f"Running IOS XR version {version} with BGP and RPKI configured, which may allow an unauthenticated"
            "attacker "
            "to crash the BGP process by sending crafted RTR packets. "
            "For more information, see "
            "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xrbgp-rpki-dos-gvmjqxbk"
        )
