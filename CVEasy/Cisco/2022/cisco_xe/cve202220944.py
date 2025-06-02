from comfy import high


@high(
    name='rule_cve202220944',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_platform='show inventory | include Chassis',
        check_secure_boot='show platform software authenticity'
    ),
)
def rule_cve202220944(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2022-20944 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to improper verification of digital signatures during the boot process
    in Catalyst 9200 Series Switches. An unauthenticated, physical attacker could exploit this
    vulnerability by loading unsigned code at system boot time, allowing them to bypass image
    verification and execute arbitrary code.
    """
    # Extract the platform information
    platform_output = commands.check_platform

    # Check if the device is a Catalyst 9200 Series
    is_cat9200 = 'C92' in platform_output

    # If not a Catalyst 9200 device, it's not vulnerable
    if not is_cat9200:
        return

    # Extract the output of the command to check secure boot status
    secure_boot_output = commands.check_secure_boot

    # Check if secure boot is disabled or not properly configured
    secure_boot_disabled = (
        'Image verification is disabled' in secure_boot_output or
        'Secure Boot: disabled' in secure_boot_output or
        not secure_boot_output  # If no output, assume it's not properly configured
    )

    # Assert that the device is not vulnerable
    assert not secure_boot_disabled, (
        f"Device {device.name} is vulnerable to CVE-2022-20944. "
        "The device is a Catalyst 9200 Series switch with image verification disabled or not properly configured, "
        "which could allow an attacker with physical access to execute unsigned code at boot time. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-xe-cat-verify-D4NEQA6q"
    )
