from comfy import medium


@medium(
    name='rule_3318_set_ip_authentication_key_chain_eigrp',
    platform=['cisco_ios', 'cisco_xe'],
    commands={'interface_eigrp_key_chain_config': 'sh run int {interface_name} | incl key-chain'}
)
def rule_3318_set_ip_authentication_key_chain_eigrp(commands, ref):
    # Extracting the EIGRP key chain configuration for the specific interface from the command output
    interface_eigrp_key_chain_config = commands.interface_eigrp_key_chain_config

    # Verifying that the EIGRP authentication key chain is properly configured on the interface
    assert 'ip authentication key-chain eigrp' in interface_eigrp_key_chain_config, ref
