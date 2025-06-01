from comfy import high


@high(
    name='rule_cve202220676',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_tcl='show running-config | include tclsh'
    ),
)
def rule_cve202220676(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2022-20676 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to insufficient input validation of data that is passed into the Tcl interpreter.
    An authenticated, local attacker with privilege level 15 could exploit this vulnerability by loading
    malicious Tcl code on an affected device, allowing them to escalate to root-level privileges.
    """
    # Extract the output of the command to check Tcl configuration
    tcl_output = commands.check_tcl

    # Check if Tcl shell access is enabled
    tcl_enabled = 'tclsh' in tcl_output

    # Assert that the device is not vulnerable
    assert not tcl_enabled, (
        f"Device {device.name} is vulnerable to CVE-2022-20676. "
        "The device has Tcl shell access enabled, "
        "which could allow an authenticated attacker with privilege level 15 to escalate to root privileges. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-priv-esc-grbtubU"
    )
