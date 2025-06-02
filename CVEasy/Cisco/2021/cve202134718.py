from comfy import high
import re


@high(
    name='rule_cve202134718',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version',
        check_ssh='show running-config | include ssh|scp'
    ),
)
def rule_cve202134718(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-34718 vulnerability in Cisco IOS XR Software.
    The vulnerability is due to insufficient input validation of arguments that are supplied
    by the user for SCP file transfer method. An authenticated, remote attacker with low privileges
    could exploit this vulnerability by specifying crafted SCP parameters when authenticating to a device,
    allowing them to elevate privileges and read/write arbitrary files on the device.
    """
    version_output = commands.show_version
    ssh_output = commands.check_ssh

    # Extract version string like '6.7.2' or '7.3.1'
    match = re.search(r'Version\s+(\d+\.\d+\.\d+)', version_output)
    if not match:
        return  # Could not determine version

    version = match.group(1)
    major, minor, patch = map(int, version.split("."))

    # Determine if version is vulnerable
    vulnerable = (
        (major == 6 and (minor < 8 or (minor == 8 and patch < 1))) or
        (major == 7 and (
            (minor == 3 and patch < 2) or
            (minor == 4 and patch < 1)
        ))
    )

    # Check if SSH/SCP is enabled
    ssh_enabled = any(feature in ssh_output for feature in [
        'ssh server',
        'scp server'
    ])

    # Check if there are users with low privileges that can use SSH/SCP
    has_ssh_access = any(
        'ssh' in line and not any(role in line.lower() for role in ['root', 'admin'])
        for line in ssh_output.splitlines()
    )

    is_configured_risky = ssh_enabled and has_ssh_access

    # Device is vulnerable if version is vulnerable and config is risky
    if vulnerable and is_configured_risky:
        assert False, (
            f"Device {device.name} is vulnerable to CVE-2021-34718. "
            f"Running IOS XR version {version} with SSH/SCP enabled and low-privilege user access, which could allow "
            "an authenticated attacker to read/write arbitrary files via crafted SCP parameters. "
            "For more information, see "
            "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-scp-inject-QwZOCv2"
        )
