from comfy import high


@high(
    name='rule_cve202320236',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version',
        check_ipxe='show running-config | include ipxe'
    ),
)
def rule_cve202320236(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2023-20236 vulnerability in Cisco IOS XR Software.
    The vulnerability is due to insufficient image verification in the iPXE boot function.
    An attacker could exploit this vulnerability by manipulating the boot parameters for image
    verification during the iPXE boot process, allowing them to install an unverified software image.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # 5.2 versions
        '5.2.0', '5.2.1', '5.2.2', '5.2.3', '5.2.4', '5.2.5', '5.2.47',
        # 5.3 versions
        '5.3.0', '5.3.1', '5.3.2', '5.3.3', '5.3.4',
        # 6.0 versions
        '6.0.0', '6.0.1', '6.0.2',
        # 6.1 versions
        '6.1.1', '6.1.2', '6.1.3', '6.1.4', '6.1.12', '6.1.22', '6.1.32',
        '6.1.36', '6.1.42',
        # 6.2 versions
        '6.2.1', '6.2.2', '6.2.3', '6.2.25', '6.2.11',
        # 6.3 versions
        '6.3.2', '6.3.3', '6.3.15',
        # 6.4 versions
        '6.4.1', '6.4.2', '6.4.3',
        # 6.5 versions
        '6.5.1', '6.5.2', '6.5.3', '6.5.25', '6.5.26', '6.5.28', '6.5.29',
        '6.5.32', '6.5.33',
        # 6.6 versions
        '6.6.2', '6.6.3', '6.6.25', '6.6.4',
        # 6.7 versions
        '6.7.1', '6.7.2', '6.7.3', '6.7.4',
        # 6.8 versions
        '6.8.1', '6.8.2',
        # 6.9 versions
        '6.9.1', '6.9.2',
        # 7.0 versions
        '7.0.1', '7.0.2', '7.0.12', '7.0.14',
        # 7.1 versions
        '7.1.1', '7.1.15', '7.1.2', '7.1.3',
        # 7.2 versions
        '7.2.0', '7.2.1', '7.2.2',
        # 7.3 versions
        '7.3.1', '7.3.15', '7.3.2', '7.3.3', '7.3.5',
        # 7.4 versions
        '7.4.1', '7.4.2',
        # 7.5 versions
        '7.5.1', '7.5.2', '7.5.3', '7.5.4',
        # 7.6 versions
        '7.6.1', '7.6.2',
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

    # Extract the output of the command to check iPXE configuration
    ipxe_output = commands.check_ipxe

    # Check if iPXE is configured
    ipxe_configured = 'ipxe' in ipxe_output

    # Assert that the device is not vulnerable
    assert not ipxe_configured, (
        f"Device {device.name} is vulnerable to CVE-2023-20236. "
        "The device is running a vulnerable version AND has iPXE configured, "
        "which could allow an attacker to install unverified software images. "
        "For more information, see"
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-"
        "sa-iosxr-ipxe-sigbypass-pymfyqgB"
    )
