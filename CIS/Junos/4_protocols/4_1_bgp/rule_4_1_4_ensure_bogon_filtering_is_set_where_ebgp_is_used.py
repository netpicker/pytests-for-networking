from comfy.compliance import low


@low(
      name='rule_4_1_4_ensure_bogon_filtering_is_set_where_ebgp_is_used',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_4_1_4_ensure_bogon_filtering_is_set_where_ebgp_is_used(commands, ref):
    assert '' in commands.chk_cmd, ref
