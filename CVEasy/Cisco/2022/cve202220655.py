from comfy import high
import re


@high(
    name="rule_cve202220655",
    platform=["cisco_iosxr"],
    commands=dict(
        show_version="show version",
    ),
)
def rule_cve202220655(configuration, commands, device, devices):
    """
    CVE-2022-20655: Multiple Cisco Products CLI Command Injection Vulnerability
    This affects IOS XR (64-bit) and SD-WAN systems. The vulnerability allows local
    authenticated users to inject OS commands with root privileges.
    """

    version_output = commands.show_version

    # Platform check
    if not any(p in version_output for p in [
        "IOS XR", "IOS XE", "vEdge", "vBond", "vSmart", "vManage", "NFVIS", "Ultra", "NSO", "VTS"
    ]):
        return

    match = re.search(r"version\s+([\w\.\(\)\-]+)", version_output, re.IGNORECASE)
    if not match:
        return

    version = match.group(1)

    def parse_version(v):
        return [int(x) if x.isdigit() else x for x in re.split(r"[.\(\)\-]+", v) if x]

    v = parse_version(version)
    is_safe = False

    # Example logic (IOS XR 7.x)
    if v[:2] == parse_version("7.0")[:2]:
        is_safe = v >= parse_version("7.0.2")
    elif v[:2] == parse_version("7.1")[:2]:
        is_safe = v >= parse_version("7.1.1")
    elif v[:2] == parse_version("6.5")[:2]:
        is_safe = v >= parse_version("6.5.32")

    assert is_safe, (
        f"Device {device.name or device.ipaddress or 'unknown'} is vulnerable to CVE-2022-20655. "
        "Please upgrade to a fixed release. "
        "See: "
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cli-cmdinj-4MttWZPB"
    )
