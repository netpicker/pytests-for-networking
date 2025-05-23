from comfy import high


@high(
    name='rule_cve202220920',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        check_ssh='show running-config | include ip ssh'
    ),
)
def rule_cve202220920(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2022-20920 vulnerability in Cisco IOS Software.
    The vulnerability is due to improper handling of resources during an exceptional situation in the SSH implementation.
    An authenticated, remote attacker could exploit this vulnerability by continuously connecting to an affected device
    and sending specific SSH requests, causing the device to reload and resulting in a denial of service (DoS) condition.
    """
    # Extract the output of the command to check SSH configuration
    ssh_output = commands.check_ssh

    # Check if SSH is enabled
    ssh_enabled = 'ip ssh' in ssh_output

    # Assert that the device is not vulnerable
    assert not ssh_enabled, (
        f"Device {device.name} is vulnerable to CVE-2022-20920. "
        "The device has SSH enabled, "
        "which could allow an authenticated attacker to cause a denial of service through crafted SSH requests. "
        "For more information, see "
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ssh-excpt-dos-FzOBQTnk"
    )
