from comfy.compliance import low


@low(
      name='rule_5_5_ensure_snmp_write_access_is_not_set',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_5_5_ensure_snmp_write_access_is_not_set(commands, ref):
    assert '' in commands.chk_cmd, ref
