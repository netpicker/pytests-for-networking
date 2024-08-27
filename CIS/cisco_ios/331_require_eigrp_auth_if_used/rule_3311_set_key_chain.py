from comfy import medium


@medium(
    name='rule_3311_set_key_chain',
    platform=['cisco_ios', 'cisco_xe'],
    commands={'key_chain_config': 'sh run | sec key chain'}
)
def rule_3331_set_key_chain(commands, ref):
    # Extracting the key chain configuration from the command output
    key_chain_config = commands.key_chain_config

    # Verifying that a key chain is configured for EIGRP
    assert 'key chain' in key_chain_config, ref
