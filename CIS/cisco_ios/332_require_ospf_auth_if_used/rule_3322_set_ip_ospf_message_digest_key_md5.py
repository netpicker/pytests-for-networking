from comfy import medium


@medium(
    name='rule_3322_set_ip_ospf_message_digest_key_md5',
    platform=['cisco_ios', 'cisco_xe'],
    commands={'interface_config': 'sh run int {interface_name}'}
)
def rule_3322_set_ip_ospf_message_digest_key_md5(commands, ref):
    # Replace {interface_name} with the actual interface you want to test in the command dictionary or
    # modify the rule to iterate through a list of interfaces if needed.

    # Extracting the OSPF MD5 key configuration from the command output
    interface_config = commands.interface_config

    # Verifying the presence of the OSPF MD5 key in the interface configuration
    assert 'ip ospf message-digest-key' in interface_config and 'md5' in interface_config, ref
