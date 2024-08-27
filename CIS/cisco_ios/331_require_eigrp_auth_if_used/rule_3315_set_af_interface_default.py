from comfy import medium


@medium(
    name='rule_3315_set_af_interface_default',
    platform=['cisco_ios', 'cisco_xe'],
    commands={'eigrp_af_config': 'sh run | sec router eigrp'}
)
def rule_3315_set_af_interface_default(commands, ref):
    # Extracting the EIGRP address family interface configuration from the command output
    eigrp_af_config = commands.eigrp_af_config

    # Verifying that 'af-interface default' is configured within the EIGRP address family
    assert 'af-interface default' in eigrp_af_config, ref
