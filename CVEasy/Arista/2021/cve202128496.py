from comfy import high


@high(
    name='rule_cve202128496',
    platform=['arista_eos'],
    commands=dict(
        show_version='show version',
        show_bfd='show running-config | section bfd',
        show_eapi='show management api http-commands'
    ),
)
def rule_cve202128496(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-28496 vulnerability in Arista EOS devices.
    The vulnerability allows BFD shared secret passwords to be leaked when displaying output
    over eAPI or other JSON outputs to authenticated users on the device.
    """
    # Extract the version information from the command output
    version_output = str(commands.show_version)

    # List of vulnerable software versions
    vulnerable_versions = [
        # 4.22.x versions (all releases)
        '4.22.0', '4.22.12',
        # 4.23.x versions (up to 4.23.9)
        '4.23.0', '4.23.9',
        # 4.24.x versions (up to 4.24.7)
        '4.24.0', '4.24.7',
        # 4.25.x versions (up to 4.25.4)
        '4.25.0', '4.25.4',
        # 4.26.x versions (up to 4.26.1)
        '4.26.0', '4.26.1'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if BFD is configured with shared secret profiles
    bfd_config = str(commands.show_bfd)
    has_bfd_secrets = 'profile' in bfd_config and 'key-id' in bfd_config

    # Check if eAPI is enabled
    eapi_config = str(commands.show_eapi)
    eapi_enabled = 'enabled' in eapi_config.lower()

    # Device is vulnerable if using BFD shared secrets and eAPI is enabled
    is_vulnerable = has_bfd_secrets and eapi_enabled

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2021-28496. "
        "The device is running a vulnerable version AND has BFD shared secret profiles configured "
        "with eAPI enabled, which could expose sensitive password information. "
        "Recommended fixes:\n"
        "1. Upgrade to one of the following fixed versions:\n"
        "  * 4.23.10 or later for 4.23.x train\n"
        "  * 4.24.8 or later for 4.24.x train\n"
        "  * 4.25.5 or later for 4.25.x train\n"
        "  * 4.26.2 or later for 4.26.x train\n"
        "2. Or apply the appropriate hotfix:\n"
        "  * For 4.22.0 - 4.25.0: SecurityAdvisory0069Hotfix-4.22-4.25.0.swix\n"
        "  * For 4.25.1 - 4.26.1: SecurityAdvisory0069Hotfix-4.25.1-4.26.1.swix\n"
        "3. As a workaround, restrict access to CLI show commands using role-based authorization\n"
        "For more information, see"
        "https://www.arista.com/en/support/advisories-notices/security-advisory/13243-security-advisory-0069"
    )
