from comfy import high
import re


@high(
    name='rule_cve202134720',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version',
        check_ipsla='show running-config | include ip sla|twamp'
    ),
)
def rule_cve202134720(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-34720 vulnerability in Cisco IOS XR Software.
    The vulnerability is due to mishandling of socket creation failures during IP SLA and TWAMP processes.
    An unauthenticated, remote attacker could exploit this vulnerability by sending specific IP SLA or
    TWAMP packets to an affected device, causing packet memory exhaustion or IP SLA process crash,
    resulting in a denial of service condition.
    """
    version_output = commands.show_version
    ipsla_output = commands.check_ipsla

    # Extract version string like '6.5.3'
    match = re.search(r'Version\s+(\d+\.\d+\.\d+)', version_output)
    if not match:
        return  # Could not determine version

    version = match.group(1)
    major, minor, patch = map(int, version.split("."))

    # Determine vulnerability based on Cisco's advisory
    vulnerable = (
        (major == 5) or
        (major == 6 and minor in [0, 1]) or
        (major == 6 and minor == 2 and patch in [1, 2]) or
        (major == 6 and minor == 3 and patch == 1) or
        (major == 6 and minor == 5 and patch in [2, 3]) or
        (major == 6 and minor == 6) or
        (major == 6 and minor == 7) or
        (major == 7 and minor == 0) or
        (major == 7 and minor == 1) or
        (major == 7 and minor == 2 and patch < 2)
    )

    # Check if IP SLA or TWAMP is configured
    has_ipsla = 'ip sla' in ipsla_output
    has_twamp = 'twamp' in ipsla_output

    if vulnerable and (has_ipsla or has_twamp):
        assert False, (
            f"Device {device.name} is vulnerable to CVE-2021-34720. "
            f"Running IOS XR version {version} with IP SLA or TWAMP configured, which may allow "
            "an unauthenticated attacker to crash the IP SLA process or exhaust memory through crafted packets. "
            "For more information, see "
            "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ipsla-ZA3SRrpP"
        )
