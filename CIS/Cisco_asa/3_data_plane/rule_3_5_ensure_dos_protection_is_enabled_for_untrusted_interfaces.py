from comfy.compliance import medium


@medium(
      name='rule_3_5_ensure_dos_protection_is_enabled_for_untrusted_interfaces',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_3_5_ensure_dos_protection_is_enabled_for_untrusted_interfaces(commands, ref):
    assert '' in commands.chk_cmd, ref
