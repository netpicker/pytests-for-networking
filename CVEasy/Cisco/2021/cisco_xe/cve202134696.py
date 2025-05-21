from comfy import high


@high(
    name='rule_cve202134696',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_platform='show inventory | include Chassis',
        check_acl='show running-config | include ip access-list|interface|ip access-group'
    ),
)
def rule_cve202134696(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-34696 vulnerability in Cisco ASR 900 and ASR 920 Series routers.
    The vulnerability in the ACL programming could allow an unauthenticated, remote attacker to
    bypass a configured ACL due to incorrect programming of hardware when an ACL is configured
    using a method other than the configuration CLI.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS XE software
    if 'IOS XE Software' not in version_output:
        return

    # Check if this is a vulnerable platform (ASR 900/920 Series)
    platform_output = commands.check_platform
    vulnerable_platforms = [
        'ASR-903', 'ASR-920',
        'ASR903', 'ASR920'
    ]
    is_vulnerable_platform = any(platform in platform_output for platform in vulnerable_platforms)

    if not is_vulnerable_platform:
        return

    # Check for ACL configuration
    acl_config = commands.check_acl

    # Check if ACLs are configured and applied to interfaces
    has_acl = 'ip access-list' in acl_config
    acl_applied = 'ip access-group' in acl_config

    # Device is vulnerable if ACLs are configured and applied
    is_vulnerable = has_acl and acl_applied

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-34696. "
        "The device is an ASR 900/920 Series router with ACLs configured and applied to interfaces, "
        "which could allow an unauthenticated remote attacker to bypass the ACLs through non-CLI configuration. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asr900acl-UeEyCxkv"
    )
