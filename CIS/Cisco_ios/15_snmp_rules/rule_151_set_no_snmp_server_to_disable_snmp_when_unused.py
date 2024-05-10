from comfy.compliance import medium


@medium(
    name='rule_151_set_no_snmp_server_to_disable_snmp_when_unused',
    platform=['cisco_ios', 'cisco_xe'],
    commands=dict(chk_cmd='show snmp community')
)
def rule_151_set_no_snmp_server_to_disable_snmp_when_unused(commands, ref):
    assert 'SNMP agent not enabled' in commands.chk_cmd, ref
