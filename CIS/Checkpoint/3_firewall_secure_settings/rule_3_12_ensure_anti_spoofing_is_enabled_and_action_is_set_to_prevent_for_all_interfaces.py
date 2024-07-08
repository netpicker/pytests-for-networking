from comfy.compliance import low


@low(
      name='rule_3_12_ensure_anti_spoofing_is_enabled_and_action_is_set_to_prevent_for_all_interfaces',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_3_12_ensure_anti_spoofing_is_enabled_and_action_is_set_to_prevent_for_all_interfaces(commands, ref):
    assert '' in commands.chk_cmd, ref
