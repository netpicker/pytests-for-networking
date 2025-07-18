from comfy import high
import re


@high(
    name="rule_cve202220650",
    platform=["cisco_nxos"],
    commands=dict(
        show_version="show version",
        show_feature_nxapi="show feature | include nxapi",
    ),
)
def rule_cve202220650(configuration, commands, device, devices):
    """
    CVE-2022-20650: NX-API command injection vulnerability in Cisco NX-OS
    An authenticated attacker could exploit the NX-API feature to run arbitrary
    OS commands as root due to improper input sanitization.
    """

    version_output = commands.show_version
    nxapi_output = commands.show_feature_nxapi

    if "nxapi" not in nxapi_output or "enabled" not in nxapi_output:
        return

    if not any(model in version_output for model in [
        "Nexus 3000", "Nexus 5500", "Nexus 5600", "Nexus 6000", "Nexus 9000"
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
    elif v[:2] == parse_version("9.3")[:2]:
        is_safe = v >= parse_version("9.3.8")

    assert is_safe, (
        f"Device {device.name or device.ipaddress or 'unknown'} is vulnerable to CVE-2022-20650. "
        "NX-API is enabled and the software version is unpatched. "
        "See: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-"
        "sa-nxos-nxapi-cmdinject-ULukNMZ2"
    )
