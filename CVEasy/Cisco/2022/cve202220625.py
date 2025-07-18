from comfy import high
import re


@high(
    name="rule_cve202220625",
    platform=["cisco_nxos"],
    commands=dict(
        show_version="show version",
        show_running_config_cdp="show running-config cdp all | include \"cdp enable\"",
    ),
)
def rule_cve202220625(configuration, commands, device, devices):
    """
    CVE-2022-20625: Cisco Discovery Protocol Service DoS Vulnerability
    An unauthenticated attacker on the local network can send crafted CDP messages
    that restart the service, possibly the whole device. This affects multiple platforms.
    """

    version_output = commands.show_version
    cdp_output = commands.show_running_config_cdp

    if "cdp enable" not in cdp_output:
        return

    if not any(model in version_output for model in [
        "Nexus 3000", "Nexus 5500", "Nexus 5600", "Nexus 6000", "Nexus 7000",
        "Nexus 9000", "UCS 6200", "UCS 6300", "UCS 6400", "Firepower 4100", "Firepower 9300",
        "MDS 9000", "Nexus 1000V"
    ]):
        return

    match = re.search(r"NXOS:\s+version\s+([\w\.\(\)]+)", version_output, re.IGNORECASE)
    if not match:
        return

    version = match.group(1)

    def parse_version(v):
        return [int(x) if x.isdigit() else x for x in re.split(r"[.\(\)I]+", v) if x]

    v = parse_version(version)
    is_safe = False

    if v[:2] == parse_version("7.0")[:2]:
        is_safe = v >= parse_version("7.0.3.I7.10")
    elif v[:2] == parse_version("8.4")[:2]:
        is_safe = v >= parse_version("8.4.5")
    elif v[:2] == parse_version("9.3")[:2]:
        is_safe = v >= parse_version("9.3.8")
    elif v[:2] == parse_version("4.1")[:2]:
        is_safe = v >= parse_version("4.1.3")
    elif v[:2] == parse_version("4.2")[:2]:
        is_safe = v >= parse_version("4.2.1")

    assert is_safe, (
        f"Device {device.name or device.ipaddress or 'unknown'} is vulnerable to CVE-2022-20625. "
        "Upgrade to a fixed version or disable CDP globally where applicable. "
        "See: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cdp-dos-G8DPLWYG"
    )
