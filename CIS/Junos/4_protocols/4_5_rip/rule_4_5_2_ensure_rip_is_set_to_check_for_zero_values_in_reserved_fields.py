from comfy.compliance import medium


@medium(
      name='rule_4_5_2_ensure_rip_is_set_to_check_for_zero_values_in_reserved_fields',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_4_5_2_ensure_rip_is_set_to_check_for_zero_values_in_reserved_fields(commands, ref):
    assert '' in commands.chk_cmd, ref
