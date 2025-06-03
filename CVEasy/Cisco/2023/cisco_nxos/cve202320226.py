from comfy import high


@high(
    name='rule_cve202320226',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_appqoe_utd='show running-config | include appqoe|utd'
    ),
)
def rule_cve202320226(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2023-20226 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to the mishandling of a crafted packet stream through the AppQoE or UTD application.
    An attacker could exploit this vulnerability by sending a crafted packet stream through an affected device,
    causing it to reload and resulting in a denial of service (DoS) condition.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions (from CVE details)
    vulnerable_versions = [
        # 17.7 versions
        '17.7.1', '17.7.1a', '17.7.2',
        # 17.8 versions
        '17.8.1', '17.8.1a',
        # 17.9 versions
        '17.9.1', '17.9.2', '17.9.1a', '17.9.2a',
        # 17.10 versions
        '17.10.1', '17.10.1a'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Extract the output of the command to check AppQoE and UTD configuration
    appqoe_utd_output = commands.check_appqoe_utd

    # Check if AppQoE or UTD is configured
    features_configured = any(feature in appqoe_utd_output for feature in ['appqoe', 'utd'])

    # Assert that the device is not vulnerable
    assert not features_configured, (
        f"Device {device.name} is vulnerable to CVE-2023-20226. "
        "The device is running a vulnerable version AND has AppQoE or UTD configured, "
        "which could allow an attacker to cause a denial of service. "
        "For more information, see"
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-appqoe-utd-dos-p8O57p5y"
    )
