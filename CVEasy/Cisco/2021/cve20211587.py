
from comfy import high


@high(
    name='rule_cve20211587',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        check_ngoam='show running-config | include feature ngoam|ngoam enable'
    ),
)
def rule_cve20211587(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-1587 vulnerability in Cisco NX-OS Software.
    The vulnerability is due to improper handling of specific packets with a TRILL OAM EtherType
    in the VXLAN OAM (NGOAM) feature. An unauthenticated, remote attacker could exploit this
    vulnerability by sending crafted packets with TRILL OAM EtherType (0x8902) to a device that
    is part of a VXLAN EVPN fabric, causing high CPU usage and system resource exhaustion.
    Note: The NGOAM feature is disabled by default.
    """
    # Extract the output of the command to check NGOAM configuration
    ngoam_output = commands.check_ngoam

    # Check if NGOAM is enabled
    ngoam_enabled = any(feature in ngoam_output for feature in [
        'feature ngoam',
        'ngoam enable'
    ])

    # If NGOAM is not enabled, device is not vulnerable
    if not ngoam_enabled:
        return

    # Assert that the device is not vulnerable
    assert not ngoam_enabled, (
        f"Device {device.name} is vulnerable to CVE-2021-1587. "
        "The device has NGOAM enabled, which could allow an unauthenticated attacker "
        "to cause high CPU usage and denial of service through crafted TRILL OAM packets. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-ngoam-dos-LTDb9Hv"
    )
