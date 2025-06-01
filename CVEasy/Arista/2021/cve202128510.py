from comfy import high


@high(
    name='rule_cve202128510',
    platform=['arista_eos'],
    commands=dict(
        show_version='show version',
        show_ptp='show running-config | section ptp'
    ),
)
def rule_cve202128510(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-28510 vulnerability in Arista EOS devices.
    The vulnerability allows an unauthenticated attacker to cause a DoS condition by sending
    malformed PTP packets with invalid TLV values, causing the PTP agent to restart repeatedly.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # 4.23.x versions before 4.23.11
        '4.23.0', '4.23.1', '4.23.2', '4.23.3', '4.23.4', '4.23.5',
        '4.23.6', '4.23.7', '4.23.8', '4.23.9', '4.23.10',
        # 4.24.x versions before 4.24.9
        '4.24.0', '4.24.1', '4.24.2', '4.24.3', '4.24.4', '4.24.5',
        '4.24.6', '4.24.7', '4.24.8',
        # 4.25.x versions before 4.25.7
        '4.25.0', '4.25.1', '4.25.2', '4.25.3', '4.25.4', '4.25.5',
        '4.25.6',
        # 4.26.x versions before 4.26.5
        '4.26.0', '4.26.1', '4.26.2', '4.26.3', '4.26.4',
        # 4.27.x versions before 4.27.2
        '4.27.0', '4.27.1'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if PTP is configured
    ptp_config = commands.show_ptp
    ptp_enabled = 'ptp' in ptp_config.lower()

    # Device is vulnerable if running affected version and PTP is enabled
    is_vulnerable = version_vulnerable and ptp_enabled

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2021-28510. "
        "The device is running a vulnerable version AND has PTP enabled, "
        "which could allow an attacker to cause a denial of service by sending malformed PTP packets. "
        "Recommended fixes:\n"
        "1. Upgrade to one of the following fixed versions:\n"
        "  * 4.27.2 or later for 4.27.x train\n"
        "  * 4.26.5 or later for 4.26.x train\n"
        "  * 4.25.7 or later for 4.25.x train\n"
        "  * 4.24.9 or later for 4.24.x train\n"
        "  * 4.23.11 or later for 4.23.x train\n"
        "2. Until upgrade is complete, implement this workaround:\n"
        "  * Install ACL rules to drop PTP packets from untrusted sources\n"
        "  * Block access to untrusted (non-management) networks\n"
        "3. A hotfix is available:\n"
        "  * SecurityAdvisory76_CVE-2021-28510_Hotfix.swix\n"
        "  * Note: Installing/uninstalling will cause PTP agent to restart\n"
        "For more information, see https://www.arista.com/en/support/advisories-notices/security-advisory/15439-security-advisory-0076"
    )
