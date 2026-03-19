import re
from comfy import high

@high(
    name='rule_cve202530653',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_mpls='show configuration protocols mpls | display set',
        show_rpd_crashes='show system core-dumps | match rpd'
    ),
)
def rule_cve202530653(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-30653 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows an unauthenticated, adjacent attacker to cause DoS
    by triggering rpd crashes when MPLS LSP is configured with node-link-protection
    and transport-class, and the LSP flaps.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable version ranges
    vulnerable_versions = []
    
    # All versions before 22.2R3-S4
    vulnerable_versions.extend([
        '21.1R', '21.2R', '21.3R', '21.4R',
        '22.1R', '22.2R1', '22.2R2', '22.2R3', '22.2R3-S1', '22.2R3-S2', '22.2R3-S3'
    ])
    
    # 22.4 versions before 22.4R3-S2
    vulnerable_versions.extend([
        '22.4R1', '22.4R2', '22.4R3', '22.4R3-S1'
    ])
    
    # 23.2 versions before 23.2R2
    vulnerable_versions.extend([
        '23.2R1', '23.2R1-S1', '23.2R1-S2'
    ])
    
    # 23.4 versions before 23.4R2
    vulnerable_versions.extend([
        '23.4R1', '23.4R1-S1', '23.4R1-S2'
    ])

    # Check if the current version is vulnerable
    version_match = re.search(r'Junos:\s+(\S+)', version_output)
    extracted_version = version_match.group(1) if version_match else ""
    version_vulnerable = extracted_version in vulnerable_versions

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check for vulnerable MPLS LSP configuration
    mpls_config = commands.show_config_mpls
    
    # Check if MPLS LSP is configured with both node-link-protection and transport-class
    has_node_link_protection = 'node-link-protection' in mpls_config
    has_transport_class = 'transport-class' in mpls_config
    has_lsp_config = 'label-switched-path' in mpls_config
    
    is_vulnerable_config = has_lsp_config and has_node_link_protection and has_transport_class

    # Check for rpd crashes
    rpd_crashes = commands.show_rpd_crashes
    has_rpd_crashes = 'rpd' in rpd_crashes and '.core' in rpd_crashes

    # Assert that the device is not vulnerable
    assert not (is_vulnerable_config or has_rpd_crashes), (
        f"Device {device.name} is vulnerable to CVE-2025-30653. "
        "The device is running a vulnerable version of Junos OS with MPLS LSP configured "
        "with node-link-protection and transport-class, which makes it susceptible to rpd crashes "
        "and Denial of Service when LSP flaps. "
        "For more information, see https://supportportal.juniper.net/JSA88888"
    )