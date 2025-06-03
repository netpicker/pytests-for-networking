from comfy import high


@high(
    name='rule_cve202320135',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version',
        check_install='show install active summary'
    ),
)
def rule_cve202320135(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2023-20135 vulnerability in Cisco IOS XR Software.
    The vulnerability is due to a time-of-check, time-of-use (TOCTOU) race condition when an install query
    regarding an ISO image is performed during an install operation that uses an ISO image.
    An attacker could exploit this vulnerability by modifying an ISO image and then carrying out install
    requests in parallel.
    A successful exploit could allow the attacker to execute arbitrary code on an affected device.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # 7.5 versions
        '7.5.2', '7.5.3', '7.5.4',
        # 7.7 versions
        '7.7.1', '7.7.2', '7.7.21',
        # 7.8 versions
        '7.8.1', '7.8.2',
        # 7.9 versions
        '7.9.1', '7.9.2'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Extract the output of the command to check install configuration
    install_output = commands.check_install

    # Check if any suspicious install operations are present
    install_issue_detected = 'install' in install_output

    # Assert that the device is not vulnerable
    assert not install_issue_detected, (
        f"Device {device.name} is vulnerable to CVE-2023-20135. "
        "The device is running a vulnerable version AND has suspicious install operations, "
        "which could allow an attacker to execute arbitrary code. "
        "For more information, see"
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-lnt-L9zOkBz5"
    )
