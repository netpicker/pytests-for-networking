from comfy.compliance import medium


@medium(
      name='rule_5_8_ensure_interface_restrictions_are_set_for_snmp',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_5_8_ensure_interface_restrictions_are_set_for_snmp(commands, ref):
    assert '' in commands.chk_cmd, ref
