from comfy import high
import re


@high(
    name='rule_cve202220623',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        check_bfd='show running-config | include feature bfd'
    ),
)
def rule_cve202220623(configuration, commands, device, devices):
    """
    CVE-2022-20623: BFD DoS vulnerability in Cisco NX-OS.
    Affects Nexus 9500 Series switches with BFD enabled on:
      - NX-OS versions < 7.0.3.I7.10
      - NX-OS versions < 9.3(8)
      - NX-OS 10.2(2) *only* if GX ASIC is in use (not checked here)
    Note: Nexus 9200/9300 not affected even on same NX-OS versions.
    """
    version_output = commands.show_version
    bfd_output = commands.check_bfd

    # Skip if BFD is not enabled
    if 'feature bfd' not in bfd_output:
        return

    # Skip if platform is not Nexus 9500
    if 'Nexus 9500' not in version_output:
        return

    # Extract NX-OS version
    match = re.search(r'NXOS:\s+version\s+([\w\.\(\)]+)', version_output, re.IGNORECASE)
    if not match:
        return

    version = match.group(1)

    def parse_version(v):
        return [int(x) if x.isdigit() else x for x in re.split(r'[.\(\)I]+', v) if x]

    v = parse_version(version)

    # Determine the correct threshold based on major.minor version
    if v[:2] == parse_version("7.0")[:2]:
        is_safe = v >= parse_version("7.0.3.I7.10")
    elif v[:2] == parse_version("9.3")[:2]:
        is_safe = v >= parse_version("9.3.8")
    elif v[:2] == parse_version("10.2")[:2]:
        # 10.2.2 requires GX ASIC, which we're not checking — skip
        return
    else:
        # Unknown version family — skip check
        return

    # Assert only if device is vulnerable
    assert is_safe, (
        f"Device {device.name or device.ipaddress or 'unknown'} is vulnerable to CVE-2022-20623. "
        f"NX-OS version {version} on a Nexus 9500 with BFD enabled may allow denial of service. "
        "Upgrade to a fixed release or apply the appropriate SMU. "
        "See: "
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-bfd-dos-wGQXrzxn"
    )
