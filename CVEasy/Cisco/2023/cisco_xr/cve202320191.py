from comfy import high


@high(
    name='rule_cve202320191',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version',
        check_mpls_acl='show running-config | include mpls|access-list'
    ),
)
def rule_cve202320191(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2023-20191 vulnerability in Cisco IOS XR Software.
    The vulnerability is due to incomplete support for ACL processing on MPLS interfaces in the ingress direction.
    An attacker could exploit this vulnerability by attempting to send traffic through an affected device,
    which could allow the attacker to bypass an ACL on the affected device.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # 6.4 versions
        '6.4.1',
        # 6.5 versions
        '6.5.1', '6.5.2', '6.5.3',
        # 6.6 versions
        '6.6.2', '6.6.3', '6.6.25', '6.6.4',
        # 7.0 versions
        '7.0.1', '7.0.2',
        # 7.1 versions
        '7.1.1', '7.1.2',
        # 7.2 versions
        '7.2.1', '7.2.2',
        # 7.3 versions
        '7.3.1', '7.3.2', '7.3.3', '7.3.5',
        # 7.4 versions
        '7.4.1', '7.4.2',
        # 7.5 versions
        '7.5.1', '7.5.2', '7.5.3', '7.5.4',
        # 7.6 versions
        '7.6.1', '7.6.2',
        # 7.7 versions
        '7.7.1', '7.7.2',
        # 7.8 versions
        '7.8.1', '7.8.2',
        # 7.9 versions
        '7.9.1'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Extract the output of the command to check MPLS and ACL configuration
    mpls_acl_output = commands.check_mpls_acl

    # Check if MPLS and ACL are configured
    mpls_acl_configured = 'mpls' in mpls_acl_output and 'access-list' in mpls_acl_output

    # Assert that the device is not vulnerable
    assert not mpls_acl_configured, (
        f"Device {device.name} is vulnerable to CVE-2023-20191. "
        "The device is running a vulnerable version AND has ACLs configured on MPLS interfaces, "
        "which could allow an attacker to bypass ACL protections. "
        "For more information, see"
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-dnx-acl-PyzDkeYF"
    )
