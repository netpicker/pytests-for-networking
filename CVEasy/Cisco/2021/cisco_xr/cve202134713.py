from comfy import high
import re


@high(
    name='rule_cve202134713',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version',
        show_platform='show platform'
    ),
)
def rule_cve202134713(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-34713 vulnerability in Cisco IOS XR Software.
    The vulnerability is due to incorrect handling of specific Ethernet frames in the Layer 2
    punt code. An unauthenticated, adjacent attacker could exploit this vulnerability by sending
    specific types of Ethernet frames, causing a spin loop that makes network processors unresponsive
    and results in line card reboot.
    """
    version_output = commands.show_version
    platform_output = commands.show_platform

    # Extract version string like '6.5.2'
    match = re.search(r'Version\s+(\d+\.\d+\.\d+)', version_output)
    if not match:
        return  # Could not determine version

    version = match.group(1)
    major, minor, patch = map(int, version.split("."))

    # Affected if version >= 6.4 and < 6.6.3
    vulnerable = (
        major == 6 and (
            (minor == 4) or
            (minor == 5) or
            (minor == 6 and patch < 3)
        )
    )

    # Check if device is an ASR 9000 Series router
    is_asr9k = any(model in platform_output for model in [
        'ASR-9000',
        'ASR9K',
        'ASR 9000'
    ])

    if vulnerable and is_asr9k:
        assert False, (
            f"Device {device.name} is vulnerable to CVE-2021-34713. "
            f"Running IOS XR version {version} on an ASR 9000 Series router, which may allow "
            "an adjacent attacker to trigger line card reboot via crafted Ethernet frames. "
            "For more information, see "
            "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-npspin-QYpwdhFD"
        )
