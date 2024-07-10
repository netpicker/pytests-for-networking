from comfy.compliance import medium


@medium(
      name='rule_1_5_2_if_snmpv2_is_in_use_set_restrictions_on_access',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_1_5_2_if_snmpv2_is_in_use_set_restrictions_on_access(commands, ref):
    assert '' in commands.chk_cmd, ref
