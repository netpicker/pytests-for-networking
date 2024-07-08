from comfy.compliance import medium


@medium(
      name='rule_1_6_ensure_maximum_ram_is_installed',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_1_6_ensure_maximum_ram_is_installed(commands, ref):
    assert '' in commands.chk_cmd, ref
