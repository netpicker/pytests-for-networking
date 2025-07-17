from comfy import high
import re

@high(
    name='rule_cve202220625',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        check_cdp='show running-config | include no cdp enable|cdp enable'
    ),
)
def rule_cve202220625(configuration, commands, device, devices):
    """
    CVE-2022-20625: DoS via CDP in NX-OS.
    Vulnerable if CDP is enabled AND version is < fixed.
    Fixed in: 7.0(3)I7(10), 8.4(5), 9.3(8)
    """
    cdp_output = commands.check_cdp
    version_output = commands.show_version

    # Check if CDP is enabled
    cdp_enabled = 'cdp enable' in cdp_output
    if not cdp_enabled:
        return  # Safe

    # Extract NX-OS version
    match = re.search(r'NXOS:\s+version\s+([\w\.\(\)]+)', version_output, re.IGNORECASE)
    if not match:
        return  # Unknown version, skip

    version = match.group(1)

    def parse_version(v):
        return [int(x) if x.isdigit() else x for x in re.split(r'[\.\(\)I]+', v) if x]

    v = parse_version(version)
    is_vulnerable = False

    if version.startswith("7.0.3") and 'I' in version:
        is_vulnerable = v < parse_version("7.0.3.I7.10")
    elif version.startswith("8.4"):
        is_vulnerable = v < parse_version("8.4.5")
    elif version.startswith("9.3"):
        is_vulnerable = v < parse_version("9.3.8")

    assert not is_vulnerable, (
        f"Device {device.name or device.ipaddress or 'unknown'} is vulnerable to CVE-2022-20625. "
        f"NX-OS version {version} with CDP enabled allows an adjacent attacker to crash the service or device. "
        "Upgrade to a fixed release. "
        "See: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cdp-dos-G8DPLWYG"
    )
