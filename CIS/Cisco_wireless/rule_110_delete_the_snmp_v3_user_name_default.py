from comfy.compliance import medium


@medium(
    name='rule_110_delete_the_snmp_v3_user_name_default',
    platform=['cisco_wlc'],
    commands=dict(chk_cmd='show snmpv3user')
)
def rule_110_delete_the_snmp_v3_user_name_default(commands, ref):
    assert 'default' not in commands.chk_cmd, ref
