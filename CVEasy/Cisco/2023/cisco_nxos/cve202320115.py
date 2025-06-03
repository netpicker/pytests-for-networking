from comfy import high


@high(
    name='rule_cve202320115',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        check_sftp='show running-config | include sftp'
    ),
)
def rule_cve202320115(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2023-20115 vulnerability in Cisco NX-OS Software.
    The vulnerability is due to a logic error when verifying the user role when an SFTP connection is opened,
    which could allow an authenticated, remote attacker to download or overwrite files from the underlying
    operating system of an affected device.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        '9.2(1)', '9.2(2)', '9.2(2t)', '9.2(3)', '9.2(4)', '9.2(2v)',
        '9.3(1)', '9.3(2)', '9.3(3)', '9.3(4)', '9.3(5)', '9.3(6)', '9.3(7)', '9.3(7a)',
        '9.3(8)', '9.3(9)', '9.3(10)', '9.3(11)', '10.1(1)', '10.1(2)', '10.1(2t)',
        '10.2(1)', '10.2(1q)', '10.2(2)', '10.2(3)', '10.2(3t)', '10.2(4)', '10.2(5)',
        '10.3(1)', '10.3(2)'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Extract the output of the command to check SFTP configuration
    sftp_output = commands.check_sftp

    # Check if SFTP is configured
    sftp_configured = 'sftp' in sftp_output

    # Assert that the device is not vulnerable
    assert not sftp_configured, (
        f"Device {device.name} is vulnerable to CVE-2023-20115. "
        "The device is running a vulnerable version AND has SFTP configured, "
        "which could allow an attacker to download or overwrite files. "
        "For more information, see"
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-sftp-xVAp5Hfd"
    )
