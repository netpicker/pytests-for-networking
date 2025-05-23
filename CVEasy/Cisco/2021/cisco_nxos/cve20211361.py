
from comfy import high


@high(
    name='rule_cve20211361',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        check_platform='show inventory | include Chassis'
    ),
)
def rule_cve20211361(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-1361 vulnerability in Cisco NX-OS Software.
    The vulnerability is due to incorrect configuration of TCP port 9075 that listens and responds
    to external connection requests. An unauthenticated, remote attacker could exploit this
    vulnerability by sending crafted TCP packets to port 9075, allowing them to create, delete,
    or overwrite arbitrary files with root privileges on the device.
    """
    # Extract the output of the commands
    version_output = commands.show_version
    platform_output = commands.check_platform

    # Check if device is a Nexus 3000 or 9000 in standalone mode
    is_n3k = 'Nexus 3000' in platform_output
    is_n9k_standalone = 'Nexus 9000' in platform_output and 'ACI' not in version_output

    # If not a Nexus 3000 or standalone 9000, device is not vulnerable
    if not (is_n3k or is_n9k_standalone):
        return

    # Device is vulnerable if it's a Nexus 3000 or standalone 9000
    is_vulnerable = is_n3k or is_n9k_standalone

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2021-1361. "
        "The device is a Nexus 3000 or standalone 9000 series switch, which could allow an unauthenticated attacker "
        "to create, delete, or overwrite arbitrary files with root privileges through crafted TCP packets to port 9075. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-3000-9000-fileaction-QtLzDRy2"
    )
