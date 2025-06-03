from comfy import high


@high(
    name='rule_cve202320082',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_platform='show inventory | include Chassis'
    ),
)
def rule_cve202320082(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2023-20082 vulnerability in Cisco IOS XE Software 
    for Catalyst 9300 Series Switches. The vulnerability is due to errors that occur 
    when retrieving the public release key used for image signature verification.
    An attacker could exploit this vulnerability by modifying specific variables in the 
    SPI flash memory, allowing them to execute persistent code at boot time and break 
    the chain of trust.
    """
    # Extract the output of the command to check platform type
    platform_output = commands.check_platform

    # Check if the device is a Catalyst 9300 Series Switch
    is_cat9300 = 'C9300' in platform_output

    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if version is before 16.11.1 (more vulnerable)
    version_pre_16_11_1 = not any(ver in version_output for ver in ['16.11.1', '16.12', '17.'])

    # Assert that the device is not vulnerable
    assert not (is_cat9300 and version_pre_16_11_1), (
        f"Device {device.name} is vulnerable to CVE-2023-20082. "
        "The device is a Catalyst 9300 Series Switch running a version before 16.11.1, "
        "which could allow an attacker to execute persistent code at boot time. "
        "For more information, see"
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-c9300-spi-ace-yejYgnNQ"
    )
