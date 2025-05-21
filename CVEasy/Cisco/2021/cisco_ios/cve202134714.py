from comfy import high


@high(
    name='rule_cve202134714',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        check_udld='show running-config | include udld'
    ),
)
def rule_cve202134714(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-34714 vulnerability in Cisco IOS Software.
    The vulnerability is due to improper input validation of UDLD packets. An unauthenticated,
    adjacent attacker could exploit this vulnerability by sending specifically crafted UDLD packets
    to an affected device, causing it to reload and resulting in a denial of service condition.
    Note: The UDLD feature is disabled by default.
    """
    # Extract the output of the command to check UDLD configuration
    udld_output = commands.check_udld

    # Check if UDLD is enabled
    udld_enabled = 'udld enable' in udld_output

    # If UDLD is not enabled, device is not vulnerable
    if not udld_enabled:
        return

    # Assert that the device is not vulnerable
    assert not udld_enabled, (
        f"Device {device.name} is vulnerable to CVE-2021-34714. "
        "The device has UDLD enabled, which could allow an adjacent attacker "
        "to cause a denial of service through crafted UDLD packets. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-nxos-xr-udld-dos-W5hGHgtQ"
    )
