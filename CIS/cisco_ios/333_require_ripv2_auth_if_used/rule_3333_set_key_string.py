from comfy import medium


@medium(
    name='rule_3333_set_key_string',
    platform=['cisco_ios', 'cisco_xe'],
    commands={'key_chain_detail': 'sh run | sec key chain'}
)
def rule_3333_set_key_string(commands, ref):
    # Extracting the key chain configuration from the command output
    key_chain_detail = commands.key_chain_detail

    # Verifying that the 'key-string' is configured within the key chain
    assert 'key-string' in key_chain_detail, ref
