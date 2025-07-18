from comfy import high
import re


@high(
    name="rule_cve202220676",
    platform=["cisco_xe"],
    commands=dict(
        show_version="show version",
        show_running_config_include_tclsh="show running-config | include tclsh",
    ),
)
def rule_cve202220676(configuration, commands, device, devices):
    """
    CVE-2022-20676: Cisco IOS XE Tool Command Language Privilege Escalation Vulnerability
    An authenticated user with privilege level 15 can exploit improper input validation in
    the Tcl interpreter to gain root access via malicious Tcl code.
    """

    config_output = commands.show_running_config_include_tclsh
    version_output = commands.show_version

    # 1. Skip if 'no tclsh' or tclsh not configured
    if not config_output or "no tclsh" in config_output.lower() or "tclsh" not in config_output:
        return

    # 2. Ensure platform is IOS XE
    if "ios xe" not in version_output.lower():
        return

    # 3. Parse version safely
    match = re.search(r"Version\s+([\w\.\(\)]+)", version_output, re.IGNORECASE)
    if not match:
        return  # Skip malformed version strings

    # 4. Raise alert — this is a detection-only rule
    assert False, (
        f"Device {device.name or device.ipaddress or 'unknown'} is potentially vulnerable to CVE-2022-20676. "
        "Tcl shell is enabled. Use Cisco Software Checker to determine the fixed version. "
        "See: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-priv-esc-grbtubU"
    )
