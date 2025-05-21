
from comfy import high


@high(
    name='rule_cve202134720',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version',
        check_ipsla='show running-config | include ip sla|twamp'
    ),
)
def rule_cve202134720(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-34720 vulnerability in Cisco IOS XR Software.
    The vulnerability is due to mishandling of socket creation failures during IP SLA and TWAMP processes.
    An unauthenticated, remote attacker could exploit this vulnerability by sending specific IP SLA or
    TWAMP packets to an affected device, causing packet memory exhaustion or IP SLA process crash,
    resulting in a denial of service condition.
    """
    # Extract the output of the commands
    version_output = commands.show_version
    ipsla_output = commands.check_ipsla

    # Check if IP SLA or TWAMP is configured
    has_ipsla = 'ip sla' in ipsla_output
    has_twamp = 'twamp' in ipsla_output

    # If neither IP SLA nor TWAMP is configured, device is not vulnerable
    if not (has_ipsla or has_twamp):
        return

    # Assert that the device is not vulnerable
    assert not (has_ipsla or has_twamp), (
        f"Device {device.name} is vulnerable to CVE-2021-34720. "
        "The device has IP SLA or TWAMP configured, which could allow an unauthenticated attacker "
        "to cause a denial of service through packet memory exhaustion or IP SLA process crash. "
        ""For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ipsla-ZA3SRrpP""
    )
