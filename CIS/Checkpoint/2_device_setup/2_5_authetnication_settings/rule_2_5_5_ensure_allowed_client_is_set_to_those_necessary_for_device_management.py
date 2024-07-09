from comfy.compliance import low


@low(
      name='rule_2_5_5_ensure_allowed_client_is_set_to_those_necessary_for_device_management',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_2_5_5_ensure_allowed_client_is_set_to_those_necessary_for_device_management(commands, ref):
    assert '' in commands.chk_cmd, ref
