from comfy import medium


@medium(
    name='rule_3312_set_key',
    platform=['cisco_ios', 'cisco_xe'],
    commands={'key_chain_config': 'sh run | sec key chain'}
)
def rule_3332_set_key(commands, ref):
    # Extracting the key chain configuration from the command output
    key_chain_config = commands.key_chain_config

    # Verifying that the key is properly set within a key chain
    assert 'key' in key_chain_config, ref
