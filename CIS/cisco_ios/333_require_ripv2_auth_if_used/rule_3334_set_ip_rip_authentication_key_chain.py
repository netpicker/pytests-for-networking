from comfy import medium


@medium(
    name='rule_3334_set_ip_rip_authentication_key_chain',
    platform=['cisco_ios', 'cisco_xe'],
    commands={'interface_rip_config': 'sh run int {interface_name}'}
)
def rule_3334_set_ip_rip_authentication_key_chain(commands, ref):
    # Replace {interface_name} and {rip_key-chain_name} with the actual interface and key chain names you want to test.

    # Extracting the RIP v2 authentication configuration from the command output
    interface_rip_config = commands.interface_rip_config

    # Verifying that the RIP v2 authentication key chain is properly configured on the interface
    assert 'ip rip authentication key-chain' in interface_rip_config, ref
