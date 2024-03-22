from comfy.compliance import medium


@medium(
    name='rule_19_ensure_snmp_v2c_mode_is_disabled',
    platform=['cisco_wlc'],
    commands=dict(chk_cmd='show snmpversion')
)
def rule_19_ensure_snmp_v2c_mode_is_disabled(commands, ref):
    assert 'SNMP v2c Mode.................................... Disable' in commands.chk_cmd, ref
