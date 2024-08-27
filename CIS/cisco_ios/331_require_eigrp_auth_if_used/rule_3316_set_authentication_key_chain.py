from comfy import medium


@medium(
    name='rule_3316_set_authentication_key_chain',
    platform=['cisco_ios', 'cisco_xe'],
    commands={'eigrp_key_chain_config': 'sh run | sec router eigrp'}
)
def rule_3316_set_authentication_key_chain(commands, ref):
    # Extracting the EIGRP address family key chain configuration from the command output
    eigrp_key_chain_config = commands.eigrp_key_chain_config

    # Verifying that the 'authentication key-chain' is set within the EIGRP address family configuration
    assert 'authentication key-chain' in eigrp_key_chain_config, ref
