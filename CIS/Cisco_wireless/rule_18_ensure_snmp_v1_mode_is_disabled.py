from comfy.compliance import medium


@medium(
    name='rule_18_ensure_snmp_v1_mode_is_disabled',
    platform=['cisco_wlc'],
    commands=dict(chk_cmd='show snmpversion')
)
def rule_18_ensure_snmp_v1_mode_is_disabled(commands, ref):
    assert 'SNMP v1 Mode.................................... Disable' in commands.chk_cmd, ref
