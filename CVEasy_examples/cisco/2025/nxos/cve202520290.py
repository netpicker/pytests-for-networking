from comfy import medium

@medium(
    name='rule_cve202520290',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        show_logging='show logging logfile | include password|secret|key',
        show_running_config='show running-config | include logging'
    ),
)
def rule_cve202520290(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2025-20290 vulnerability in Cisco NX-OS Software.
    The vulnerability allows an authenticated, local attacker to access sensitive
    information such as stored credentials through improperly logged information
    in log files on the file system.
    """
    # Extract the version information from the command output
    version_output = commands.show_version or ''

    # List of vulnerable versions based on the advisory
    # All versions are vulnerable until fixed releases
    vulnerable_version_patterns = [
        # Nexus 3000/9000 Series - vulnerable versions
        '6.0(2)', '7.0(3)', '9.2', '9.3', '10.1', '10.2', '10.3', '10.4'
    ]

    # Fixed versions for Nexus 3000/9000 Series
    fixed_versions = [
        '10.4(3)', '10.3(5)', '10.2(8)', '9.3(14)', '7.0(3)I7(11)'
    ]

    # Check if the current device's software version is vulnerable
    version_vulnerable = False
    for pattern in vulnerable_version_patterns:
        if pattern in version_output:
            # Check if it's not a fixed version
            is_fixed = any(fixed_ver in version_output for fixed_ver in fixed_versions)
            if not is_fixed:
                version_vulnerable = True
                break

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if logging is configured (which could expose sensitive information)
    logging_config = commands.show_running_config or ''
    is_logging_configured = 'logging' in logging_config.lower()

    # Check if log files contain sensitive information
    logging_output = commands.show_logging or ''
    has_sensitive_info = any(keyword in logging_output.lower() 
                            for keyword in ['password', 'secret', 'key', 'credential'])

    # Assert that the device is not vulnerable
    # Device is vulnerable if it's running a vulnerable version AND has logging configured
    # The vulnerability exists regardless of configuration, but exploitation requires
    # access to log files which are only created when logging is active
    assert not (version_vulnerable and is_logging_configured), (
        f"Device {device.name} is vulnerable to CVE-2025-20290. "
        "The device is running a vulnerable version of NX-OS Software that improperly logs sensitive information. "
        "An authenticated, local attacker with access to the file system could access sensitive information such as stored credentials from log files. "
        "Upgrade to a fixed release. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-infodis-TEcTYSFG"
    )