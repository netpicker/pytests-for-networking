from comfy.compliance import low


@low(
      name='rule_4_12_2_ensure_lldp_med_is_disabled_if_not_required',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_4_12_2_ensure_lldp_med_is_disabled_if_not_required(commands, ref):
    assert '' in commands.chk_cmd, ref
