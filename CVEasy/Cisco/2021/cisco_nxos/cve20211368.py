
from comfy import high


@high(
    name='rule_cve20211368',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        check_udld='show running-config | include udld|interface'
    ),
)
def rule_cve20211368(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-1368 vulnerability in Cisco NX-OS Software.
    The vulnerability is due to insufficient input validation in the UDLD feature.
    An unauthenticated, adjacent attacker could exploit this vulnerability by sending
    crafted UDLD packets to a directly connected device with UDLD enabled on a port channel,
    allowing them to execute arbitrary code with administrative privileges or cause a DoS condition.
    Note: The UDLD feature is disabled by default.
    """
    # Extract the output of the commands
    udld_output = commands.check_udld

    # Check if UDLD is enabled and port-channel exists
    udld_enabled = 'udld' in udld_output
    port_channel = 'interface port-channel' in udld_output

    # If UDLD is not enabled or no port-channel exists, device is not vulnerable
    if not (udld_enabled and port_channel):
        return

    # Assert that the device is not vulnerable
    assert not (udld_enabled and port_channel), (
        f"Device {device.name} is vulnerable to CVE-2021-1368. "
        "The device has UDLD enabled on a port-channel interface, which could allow an adjacent attacker "
        "to execute arbitrary code with administrative privileges or cause a denial of service. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-udld-rce-xetH6w35"
    )
