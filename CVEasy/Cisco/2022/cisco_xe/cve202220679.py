import re  # Add regex module
from comfy import high


@high(
    name='rule_cve202220679',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_ipsec='show running-config | include crypto ipsec',
        check_mtu='show interfaces | include MTU'
    ),
)
def rule_cve202220679(configuration, commands, device, devices):
    # Convert command outputs to strings to handle None values
    ipsec_output = str(commands.check_ipsec or "")
    mtu_output = str(commands.check_mtu or "")

    # Check if IPsec is configured
    ipsec_configured = 'crypto ipsec' in ipsec_output

    # Check if any interface has MTU >= 1800 using regex
    high_mtu = False
    for line in mtu_output.splitlines():
        if 'MTU' in line:
            # Use regex to find the first sequence of digits after "MTU"
            match = re.search(r'MTU.*?(\d+)', line)
            if match:
                try:
                    mtu = int(match.group(1))
                    if mtu >= 1800:
                        high_mtu = True
                        break
                except ValueError:
                    continue

    # Device is vulnerable if both conditions are met
    is_vulnerable = ipsec_configured and high_mtu

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2022-20679. "
        "The device has IPsec configured and interfaces with MTU >= 1800 bytes, "
        "which could allow an attacker to cause a denial of service. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-qfp-ipsec-GQmqvtqV"
    )
