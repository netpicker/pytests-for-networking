from comfy.compliance import medium


@medium(
      name='rule_6_19_ensure_hostname_is_not_set_to_device_make_or_model',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_19_ensure_hostname_is_not_set_to_device_make_or_model(commands, ref):
    assert '' in commands.chk_cmd, ref
