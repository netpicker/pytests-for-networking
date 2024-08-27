from comfy import medium


@medium(
    name='rule_3321_set_authentication_message_digest_for_ospf_area',
    platform=['cisco_ios'],
    commands={'ospf_config': 'sh run | sec router ospf'}
)
def rule_3321_set_authentication_message_digest_for_ospf_area(commands, ref):
    # Extracting the OSPF configuration section from the command output
    ospf_config = commands.ospf_config

    # Checking if 'authentication message-digest' is configured in the OSPF section
    assert 'area' in ospf_config and 'authentication message-digest' in ospf_config, ref
