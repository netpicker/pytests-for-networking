import re
from comfy import high


@high(
    name='rule_cve202552951',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_firewall_config='show configuration firewall | display set'
    ),
)
def rule_cve202552951(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-52951 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows an attacker sending IPv6 traffic destined to the device
    to effectively bypass any firewall filtering configured on the interface due to
    a Protection Mechanism Failure in kernel filter processing where 'payload-protocol'
    match is not being supported.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable version ranges
    vulnerable_versions = [
        # All versions before 21.2R3-S9
        '21.2R1', '21.2R2', '21.2R3', '21.2R3-S1', '21.2R3-S2', '21.2R3-S3', '21.2R3-S4', '21.2R3-S5', '21.2R3-S6', '21.2R3-S7', '21.2R3-S8',
        # From 21.4 before 21.4R3-S11
        '21.4R1', '21.4R2', '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', '21.4R3-S4', '21.4R3-S5', '21.4R3-S6', '21.4R3-S7', '21.4R3-S8', '21.4R3-S9', '21.4R3-S10',
        # From 22.2 before 22.2R3-S7
        '22.2R1', '22.2R2', '22.2R3', '22.2R3-S1', '22.2R3-S2', '22.2R3-S3', '22.2R3-S4', '22.2R3-S5', '22.2R3-S6',
        # From 22.4 before 22.4R3-S7
        '22.4R1', '22.4R2', '22.4R3', '22.4R3-S1', '22.4R3-S2', '22.4R3-S3', '22.4R3-S4', '22.4R3-S5', '22.4R3-S6',
        # From 23.2 before 23.2R2-S4
        '23.2R1', '23.2R2', '23.2R2-S1', '23.2R2-S2', '23.2R2-S3',
        # From 23.4 before 23.4R2-S5
        '23.4R1', '23.4R2', '23.4R2-S1', '23.4R2-S2', '23.4R2-S3', '23.4R2-S4',
        # From 24.2 before 24.2R2-S1
        '24.2R1', '24.2R2',
        # From 24.4 before 24.4R1-S2, 24.4R2
        '24.4R1', '24.4R1-S1', '24.4R2'
    ]

    # Check if the current version is vulnerable
    version_match = re.search(r'Junos:\s+(\S+)', version_output)
    extracted_version = version_match.group(1) if version_match else ""
    version_vulnerable = extracted_version in vulnerable_versions

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check for vulnerable firewall configuration
    firewall_config = commands.show_firewall_config

    # Check if payload-protocol is used in firewall filters
    has_payload_protocol = 'payload-protocol' in firewall_config

    # Check if firewall filters are configured for control plane protection
    has_firewall_filter = 'firewall family inet6 filter' in firewall_config or 'firewall family inet filter' in firewall_config

    # Device is vulnerable if it has firewall filters with payload-protocol match
    is_vulnerable = has_firewall_filter and has_payload_protocol

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-52951. "
        "The device is running a vulnerable version of Junos OS with firewall filters using 'payload-protocol' match, "
        "which allows attackers to bypass firewall filtering on the control plane. "
        "The 'payload-protocol' match is not being supported, causing any term containing it to accept all packets. "
        "For more information, see https://supportportal.juniper.net/JSA88133"
    )