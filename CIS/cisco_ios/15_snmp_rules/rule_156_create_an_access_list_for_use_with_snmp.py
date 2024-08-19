from comfy.compliance import medium


@medium(
    name='rule_156_create_an_access_list_for_use_with_snmp',
    platform=['cisco_ios', 'cisco_xe'],
    commands=dict(chk_cmd='sh ip access-list <<em>snmp_acl_number</em>>')
)
def rule_156_create_an_access_list_for_use_with_snmp(commands, ref):
    assert 'access-list deny any log' in commands.chk_cmd, ref
