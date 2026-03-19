import re
from comfy import high


@high(
    name='rule_cve202530659',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_svr='show configuration | display set | match "secure-vector-routing"'
    ),
)
def rule_cve202530659(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-30659 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows an unauthenticated, network-based attacker to cause a DoS
    by sending a malformed packet to a device configured for Secure Vector Routing (SVR),
    causing the PFE to crash and restart.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions
    vulnerable_versions = [
        # All 21.4 versions
        '21.4R1', '21.4R2', '21.4R3',
        # 22.2 versions before 22.2R3-S6
        '22.2R1', '22.2R2', '22.2R3', '22.2R3-S1', '22.2R3-S2', '22.2R3-S3', '22.2R3-S4', '22.2R3-S5',
        # 22.4 versions before 22.4R3-S6
        '22.4R1', '22.4R2', '22.4R3', '22.4R3-S1', '22.4R3-S2', '22.4R3-S3', '22.4R3-S4', '22.4R3-S5',
        # 23.2 versions before 23.2R2-S3
        '23.2R1', '23.2R2', '23.2R2-S1', '23.2R2-S2',
        # 23.4 versions before 23.4R2-S4
        '23.4R1', '23.4R2', '23.4R2-S1', '23.4R2-S2', '23.4R2-S3',
        # 24.2 versions before 24.2R2
        '24.2R1', '24.2R1-S1', '24.2R1-S2'
    ]

    # Check if the current version is vulnerable
    version_match = re.search(r'Junos:\s+(\S+)', version_output)
    extracted_version = version_match.group(1) if version_match else ""
    version_vulnerable = extracted_version in vulnerable_versions

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if device is SRX Series
    chassis_output = commands.show_chassis_hardware
    is_srx_platform = 'SRX' in chassis_output

    if not is_srx_platform:
        return

    # Check if Secure Vector Routing (SVR) is configured
    svr_config = commands.show_config_svr
    has_svr_configured = 'secure-vector-routing' in svr_config

    # Assert that the device is not vulnerable
    assert not has_svr_configured, (
        f"Device {device.name} is vulnerable to CVE-2025-30659. "
        "The device is running a vulnerable version of Junos OS on SRX Series hardware with "
        "Secure Vector Routing (SVR) configured, which makes it susceptible to PFE crashes "
        "when receiving specifically malformed packets. "
        "For more information, see https://supportportal.juniper.net/JSA88588"
    )