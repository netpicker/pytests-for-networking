from comfy import high


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
    # Extract the output of the commands
    version_output = commands.show_version
    ssh_output = commands.check_ssh

    # Check if SSH/SCP is enabled
    ssh_enabled = any(feature in ssh_output for feature in [
        'ssh server',
        'scp server'
    ])

    # If SSH/SCP is not enabled, device is not vulnerable
    if not ssh_enabled:
        return

    # Check if there are users with low privileges that can use SSH/SCP
    has_ssh_access = any(
        'ssh' in line and not any(role in line.lower() for role in ['root', 'admin'])
        for line in ssh_output.splitlines()
    )

    # Device is vulnerable if SSH/SCP is enabled and low privilege users have SSH access
    is_vulnerable = ssh_enabled and has_ssh_access

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2021-34718. "
        "The device has SSH/SCP enabled with low privilege user access, which could allow "
        "an authenticated attacker to read and write arbitrary files through SCP parameter injection. "
        ""For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-scp-inject-QwZOCv2""
    )
