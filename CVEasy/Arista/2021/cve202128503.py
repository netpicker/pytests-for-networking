from comfy import high


@high(
    name='rule_cve202128503',
    platform=['arista_eos'],
    commands=dict(
        show_version='show version',
        show_eapi='show management api http-commands',
        show_cert_auth='show running-config | include certificate user'
    ),
)
def rule_cve202128503(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-28503 vulnerability in Arista EOS devices.
    The vulnerability allows remote attackers to bypass authentication when certificate-based 
    authentication is used with eAPI, due to improper credential re-evaluation.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # 4.23.x versions before 4.23.10
        '4.23.0', '4.23.1', '4.23.2', '4.23.3', '4.23.4',
        '4.23.5', '4.23.6', '4.23.7', '4.23.8', '4.23.9',
        # 4.24.x versions before 4.24.8
        '4.24.0', '4.24.1', '4.24.2', '4.24.3', '4.24.4',
        '4.24.5', '4.24.6', '4.24.7',
        # 4.25.x versions before 4.25.6
        '4.25.0', '4.25.1', '4.25.2', '4.25.3', '4.25.4', '4.25.5',
        # 4.26.x versions before 4.26.3
        '4.26.0', '4.26.1', '4.26.2'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if eAPI is enabled
    eapi_config = commands.show_eapi
    eapi_enabled = 'enabled' in eapi_config.lower()

    # Check if certificate-based authentication is configured
    cert_config = commands.show_cert_auth
    cert_auth_enabled = 'certificate user' in cert_config

    # Device is vulnerable if both eAPI and certificate auth are enabled
    is_vulnerable = eapi_enabled and cert_auth_enabled

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2021-28503. "
        "The device is running a vulnerable version AND has eAPI enabled with certificate-based authentication, "
        "which could allow remote attackers to bypass authentication. "
        "Recommended fixes:\n"
        "1. Upgrade to one of the following fixed versions:\n"
        "  * 4.26.3 or later for 4.26.x train\n"
        "  * 4.25.6 or later for 4.25.x train\n"
        "  * 4.24.8 or later for 4.24.x train\n"
        "  * 4.23.10 or later for 4.23.x train\n"
        "2. Until upgrade is complete, implement this workaround:\n"
        "  * Disable certificate-based authentication for eAPI:\n"
        "    switch(config)#management security\n"
        "    switch(config-mgmt-security)#ssl profile profileEAPI\n"
        "    switch(config-mgmt-sec-ssl-profile-profileEAPI)#no trust certificate user.cert\n"
        "For more information, see https://www.arista.com/en/support/advisories-notices/security-advisory/13605-security-advisory-0072"
    )
