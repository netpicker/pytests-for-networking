from comfy import medium


@medium(
    name='rule_3314_set_address_family_ipv4_autonomous_system',
    platform=['cisco_ios', 'cisco_xe'],
    commands={'eigrp_config': 'sh run | sec router eigrp'}
)
def rule_3314_set_address_family_ipv4_autonomous_system(commands, ref):
    # Extracting the EIGRP address family configuration from the command output
    eigrp_config = commands.eigrp_config

    # Verifying that the 'address-family ipv4 autonomous-system' is configured for EIGRP
    assert 'address-family ipv4 autonomous-system' in eigrp_config, ref
