from comfy import high
import re


@high(
    name="rule_cve202220624",
    platform=["cisco_nxos"],
    commands=dict(
        show_version="show version",
        show_cfs_status="show cfs status",
    ),
)
def rule_cve202220624(configuration, commands, device, devices):
    """
    CVE-2022-20624:
    Cisco Fabric Services over IP (CFSoIP) DoS vulnerability in Cisco NX-OS.
    """

    version_output = commands.show_version
    cfs_output = commands.show_cfs_status

    # Skip if CFSoIP is not enabled
    if "Distribution over IP : Enabled" not in cfs_output:
        return

    # Skip if not one of the affected platforms
    if not any(p in version_output for p in ["Nexus 3000", "Nexus 9000", "UCS 6400"]):
        return

    # Extract NX-OS version
    match = re.search(r'NXOS:\s+version\s+([\w\.\(\)]+)', version_output)
    if not match:
        return

    version = match.group(1)

    def parse_version(v):
        return [int(x) if x.isdigit() else x for x in re.split(r'[.\(\)I]+', v) if x]

    v = parse_version(version)

    # Determine if the version is vulnerable based on platform
    if "UCS 6400" in version_output:
        # UCS 6400 fixed in: 4.1(3h), 4.2(1l)
        is_safe = (
            v >= parse_version("4.1.3h") or
            v >= parse_version("4.2.1l")
        )
    else:
        # Nexus 3000/9000 fixed in: 7.0(3)I7(10) or 9.3(8)
        if v[:2] == parse_version("7.0")[:2]:
            is_safe = v >= parse_version("7.0.3.I7.10")
        elif v[:2] == parse_version("9.3")[:2]:
            is_safe = v >= parse_version("9.3.8")
        else:
            # Unknown family — skip
            return

    # Assert only if device is vulnerable
    assert is_safe, (
        f"Device {device.name or device.ipaddress or 'unknown'} is vulnerable to CVE-2022-20624. "
        f"NX-OS version {version} with CFSoIP enabled may allow a remote DoS. "
        "Upgrade to a fixed release or apply the appropriate SMU. "
        "See: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cfsoip-dos-tpykyDr"
    )
