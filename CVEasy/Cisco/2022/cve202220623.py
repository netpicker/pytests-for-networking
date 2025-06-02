from comfy import high


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
    This rule checks for the CVE-2022-20623 vulnerability in Cisco NX-OS Software.
    The vulnerability is due to a logic error in the BFD rate limiter functionality of Nexus 9000 Series Switches.
    An unauthenticated, remote attacker could exploit this vulnerability by sending a crafted stream of traffic
    through the device, causing BFD traffic to be dropped and resulting in BFD session flaps, route instability,
    and a denial of service condition.
    """
    # Extract the platform information
    platform_output = commands.show_version

    # Check if the device is a Nexus 9000 Series
    is_n9k = 'Nexus 9000' in platform_output

    # If not a Nexus 9000 device, it's not vulnerable
    if not is_n9k:
        return

    # Extract the output of the command to check BFD configuration
    bfd_output = commands.check_bfd

    # Check if BFD is enabled
    bfd_enabled = 'feature bfd' in bfd_output

    # Assert that the device is not vulnerable
    assert not bfd_enabled, (
        f"Device {device.name} is vulnerable to CVE-2022-20623. "
        "The device is a Nexus 9000 Series switch with BFD enabled, "
        "which could allow an unauthenticated attacker to cause BFD session flaps and a denial of service "
        "through crafted traffic. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-bfd-dos-wGQXrzxn"
    )
