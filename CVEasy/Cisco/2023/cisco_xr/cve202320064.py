from comfy import high


@high(
    name='rule_cve202320064',
    platform=['cisco_xr'],
    commands=dict(
        check_grub='show running-config | include grub'
    ),
)
def rule_cve202320064(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2023-20064 vulnerability in Cisco IOS XR Software.
    The vulnerability is due to the inclusion of unnecessary commands within the GRUB environment
    that allow sensitive files to be viewed. An attacker could exploit this vulnerability by being
    connected to the console port of the Cisco IOS XR device when the device is power-cycled.
    """
    # Extract the output of the command to check GRUB configuration
    grub_output = commands.check_grub

    # Check if GRUB configuration is present
    grub_configured = 'grub' in grub_output

    # Assert that the device is not vulnerable
    assert not grub_configured, (
        f"Device {device.name} is vulnerable to CVE-2023-20064. "
        "The device has GRUB configuration that could allow an attacker to view sensitive files. "
        "For more information, see"
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-"
        "sa-iosxr-load-infodisc-9rdOr5Fq"
    )
