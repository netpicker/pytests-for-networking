from comfy.compliance import medium


@medium(
      name='rule_1_3_ensure_device_is_physically_secured',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_1_3_ensure_device_is_physically_secured(commands, ref):
    assert '' in commands.chk_cmd, ref
