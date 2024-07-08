from comfy.compliance import low


@low(
      name='rule_5_9_ensure_snmp_is_set_to_oob_management_only',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_5_9_ensure_snmp_is_set_to_oob_management_only(commands, ref):
    assert '' in commands.chk_cmd, ref
