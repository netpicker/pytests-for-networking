from comfy import high


@high(
    name='rule_cve202320185',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        check_cloudsec='show running-config | include cloudsec'
    ),
)
def rule_cve202320185(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2023-20185 vulnerability in Cisco NX-OS System Software in ACI Mode.
    The vulnerability is due to an issue with the implementation of the ciphers used by the 
    CloudSec encryption feature, which could allow an unauthenticated, remote attacker to read or modify 
    intersite encrypted traffic.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # 14.0 versions
        '14.0(1h)', '14.0(2c)', '14.0(3d)', '14.0(3c)',
        # 14.1 versions
        '14.1(1i)', '14.1(1j)', '14.1(1k)', '14.1(1l)',
        '14.1(2g)', '14.1(2m)', '14.1(2o)', '14.1(2s)',
        '14.1(2u)', '14.1(2w)', '14.1(2x)',
        # 14.2 versions
        '14.2(1i)', '14.2(1j)', '14.2(1l)', '14.2(2e)',
        '14.2(2f)', '14.2(2g)', '14.2(3j)', '14.2(3l)',
        '14.2(3n)', '14.2(3q)', '14.2(4i)', '14.2(4k)',
        '14.2(4o)', '14.2(4p)', '14.2(5k)', '14.2(5l)',
        '14.2(5n)', '14.2(6d)', '14.2(6g)', '14.2(6h)',
        '14.2(6l)', '14.2(7f)', '14.2(7l)', '14.2(6o)',
        '14.2(7q)', '14.2(7r)', '14.2(7s)', '14.2(7t)',
        '14.2(7u)', '14.2(7v)', '14.2(7w)',
        # 15.0 versions
        '15.0(1k)', '15.0(1l)', '15.0(2e)', '15.0(2h)',
        # 15.1 versions
        '15.1(1h)', '15.1(2e)', '15.1(3e)', '15.1(4c)',
        # 15.2 versions
        '15.2(1g)', '15.2(2e)', '15.2(2f)', '15.2(2g)',
        '15.2(2h)', '15.2(3e)', '15.2(3f)', '15.2(3g)',
        '15.2(4d)', '15.2(4e)', '15.2(5c)', '15.2(5d)',
        '15.2(5e)', '15.2(4f)', '15.2(6e)', '15.2(6g)',
        '15.2(7f)', '15.2(7g)', '15.2(8d)', '15.2(8e)',
        '15.2(8f)', '15.2(8g)', '15.2(8h)',
        # 16.0 versions
        '16.0(1g)', '16.0(1j)', '16.0(2h)', '16.0(2j)',
        '16.0(3d)', '16.0(3e)',
        # 15.3 versions
        '15.3(1d)',
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Extract the output of the command to check CloudSec configuration
    cloudsec_output = commands.check_cloudsec

    # Check if CloudSec is configured
    cloudsec_configured = 'cloudsec' in cloudsec_output

    # Assert that the device is not vulnerable
    assert not cloudsec_configured, (
        f"Device {device.name} is vulnerable to CVE-2023-20185. "
        "The device is running a vulnerable version AND has CloudSec configured, "
        "which could allow an attacker to read or modify intersite encrypted traffic. "
        "For more information, see"
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-"
        "sa-aci-cloudsec-enc-Vs5Wn2sX"
    )
