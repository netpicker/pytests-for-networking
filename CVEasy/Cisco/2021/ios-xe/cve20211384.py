from comfy import high


@high(
    name='rule_cve20211384',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_iox='show running-config | include iox|app-hosting'
    ),
)
def rule_cve20211384(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-1384 vulnerability in Cisco IOS XE Software's IOx environment.
    The vulnerability allows an authenticated, remote attacker to inject commands into the underlying
    operating system as the root user due to incomplete validation of fields in application packages
    loaded onto IOx.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS XE software
    if 'IOS XE Software' not in version_output:
        return

    # Check for IOx configuration
    iox_config = commands.check_iox
    iox_enabled = any(feature in iox_config for feature in [
        'iox',
        'app-hosting',
        'iox client'
    ])

    # If IOx is enabled, device is potentially vulnerable
    assert not iox_enabled, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-1384. "
        "The device has IOx application hosting enabled, which could allow an authenticated "
        "remote attacker to inject commands with root privileges through crafted application packages. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iox-cmdinj-RkSURGHG"
    )
