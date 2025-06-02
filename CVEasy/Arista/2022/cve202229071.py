from comfy import high


@high(
    name='rule_cve202229071',
    platform=['arista_eos'],
    commands=dict(
        show_version='show version',
        show_cvp_info='show cvp info'
    ),
)
def rule_cve202229071(configuration, commands, device, devices):
    """
    This rule checks for CVE-2022-29071 vulnerability in Arista CloudVision Portal (CVP).
    The vulnerability allows user passwords to be leaked in the Audit and System logs,
    which could expose sensitive information to other authenticated users.
    """
    # Extract the CVP version information from the command output
    version_output = commands.show_cvp_info

    # List of vulnerable software versions
    vulnerable_versions = [
        # CVP versions
        '2020.2', '2020.3',
        '2021.1', '2021.2', '2021.3'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if this is an on-premises deployment
    cvp_info = commands.show_cvp_info
    is_onprem = 'Deployment: On-Premises' in cvp_info

    # Device is vulnerable if it's an on-premises deployment
    is_vulnerable = is_onprem

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2022-29071. "
        "The device is running a vulnerable version of CVP in an on-premises deployment, "
        "which could allow user passwords to be leaked in Audit and System logs. "
        "Recommended fixes:\n"
        "1. Upgrade to one of the following fixed versions:\n"
        "  * CVP 2022.1.1 or later\n"
        "  * CVP 2022.2.0 or later\n"
        "2. Until upgrade is complete, implement these workarounds:\n"
        "  * Change CVP user passwords and ensure they match switch enable passwords\n"
        "  * Restrict access to CVP application and host OS to trusted users only\n"
        "  * Regularly rotate user passwords\n"
        "For more information, see"
        "https://www.arista.com/en/support/advisories-notices/security-advisory/15865-security-advisory-0079"
    )
