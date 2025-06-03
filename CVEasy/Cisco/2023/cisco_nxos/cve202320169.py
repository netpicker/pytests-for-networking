from comfy import high


@high(
    name='rule_cve202320169',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        check_isis='show running-config | include router isis'
    ),
)
def rule_cve202320169(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2023-20169 vulnerability in Cisco NX-OS Software.
    The vulnerability is due to insufficient input validation when parsing an ingress IS-IS packet,
    which could allow an unauthenticated, adjacent attacker to cause the IS-IS process to unexpectedly restart,
    resulting in a denial of service (DoS) condition.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # 10.3 versions
        '10.3(2)',
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Extract the output of the command to check IS-IS configuration
    isis_output = commands.check_isis

    # Check if IS-IS is configured
    isis_configured = 'router isis' in isis_output

    # Assert that the device is not vulnerable
    assert not isis_configured, (
        f"Device {device.name} is vulnerable to CVE-2023-20169. "
        "The device is running a vulnerable version AND has IS-IS configured, "
        "which could allow an attacker to cause a denial of service. "
        "For more information, see"
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-"
        "sa-nxos-n3_9k-isis-dos-FTCXB4Vb"
    )
