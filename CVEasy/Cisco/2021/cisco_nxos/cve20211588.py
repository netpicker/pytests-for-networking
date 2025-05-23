from comfy import high


@high(
    name='rule_cve20211588',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        check_mpls='show running-config | include feature mpls|mpls oam'
    ),
)
def rule_cve20211588(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-1588 vulnerability in Cisco NX-OS Software.
    The vulnerability is due to improper input validation when processing MPLS echo-request
    or echo-reply packets. An unauthenticated, remote attacker could exploit this vulnerability
    by sending malicious MPLS echo-request or echo-reply packets to an interface enabled for
    MPLS forwarding, causing the MPLS OAM process to crash and restart multiple times, leading
    to a device reload and denial of service condition.
    """
    # Extract the output of the command to check MPLS configuration
    mpls_output = commands.check_mpls

    # Check if MPLS is enabled and OAM is configured
    mpls_enabled = 'feature mpls' in mpls_output
    mpls_oam_enabled = 'mpls oam' in mpls_output

    # If MPLS is not enabled or OAM is not configured, device is not vulnerable
    if not (mpls_enabled and mpls_oam_enabled):
        return

    # Assert that the device is not vulnerable
    assert not (mpls_enabled and mpls_oam_enabled), (
        f"Device {device.name} is vulnerable to CVE-2021-1588. "
        "The device has MPLS and MPLS OAM enabled, which could allow an unauthenticated attacker "
        "to cause a denial of service through crafted MPLS echo packets. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-mpls-oam-dos-sGO9x5GM"
    )
