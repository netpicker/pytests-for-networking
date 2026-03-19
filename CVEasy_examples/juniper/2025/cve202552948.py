import re
from comfy import high


@high(
    name='rule_cve202552948',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_bpf='show configuration | display set | match "packet-capture"',
        show_config_firewall='show configuration | display set | match "firewall.*packet-capture"',
        show_config_interfaces='show configuration | display set | match "interfaces.*packet-capture"'
    ),
)
def rule_cve202552948(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-52948 vulnerability in Juniper Networks Junos OS.
    The vulnerability in BPF processing allows an attacker to cause FPC and system crashes
    through specific traffic patterns, especially when packet capturing is enabled.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable version ranges
    vulnerable_versions = [
        # All versions before 21.2R3-S9
        '21.2R1', '21.2R2', '21.2R3', '21.2R3-S1', '21.2R3-S2', '21.2R3-S3', '21.2R3-S4', '21.2R3-S5', '21.2R3-S6', '21.2R3-S7', '21.2R3-S8',
        # From 21.4 before 21.4R3-S10
        '21.4R1', '21.4R2', '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', '21.4R3-S4', '21.4R3-S5', '21.4R3-S6', '21.4R3-S7', '21.4R3-S8', '21.4R3-S9',
        # From 22.2 before 22.2R3-S6
        '22.2R1', '22.2R2', '22.2R3', '22.2R3-S1', '22.2R3-S2', '22.2R3-S3', '22.2R3-S4', '22.2R3-S5',
        # From 22.4 before 22.4R3-S7
        '22.4R1', '22.4R2', '22.4R3', '22.4R3-S1', '22.4R3-S2', '22.4R3-S3', '22.4R3-S4', '22.4R3-S5', '22.4R3-S6',
        # From 23.2 before 23.2R2-S3
        '23.2R1', '23.2R2', '23.2R2-S1', '23.2R2-S2',
        # From 23.4 before 23.4R2-S3
        '23.4R1', '23.4R2', '23.4R2-S1', '23.4R2-S2',
        # From 24.2 before 24.2R1-S1, 24.2R2
        '24.2R1', '24.2R2'
    ]

    # Check if the current version is vulnerable
    version_match = re.search(r'Junos:\s+(\S+)', version_output)
    extracted_version = version_match.group(1) if version_match else ""
    version_vulnerable = extracted_version in vulnerable_versions

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if packet capturing is enabled (increases likelihood of vulnerability)
    bpf_config = commands.show_config_bpf
    firewall_config = commands.show_config_firewall
    interfaces_config = commands.show_config_interfaces

    # Check for packet-capture configuration
    has_packet_capture = (
        'packet-capture' in bpf_config or
        'packet-capture' in firewall_config or
        'packet-capture' in interfaces_config
    )

    # Assert that the device is not vulnerable
    assert not (version_vulnerable and has_packet_capture), (
        f"Device {device.name} is vulnerable to CVE-2025-52948. "
        "The device is running a vulnerable version of Junos OS with packet capturing enabled, "
        "which makes it susceptible to FPC and system crashes due to BPF processing race conditions. "
        "Specific traffic patterns can trigger internal structure leakage leading to system crashes. "
        "For more information, see https://supportportal.juniper.net/JSA88588"
    )