from comfy.compliance import low


@low(
      name='rule_2_2_ensure_noproxyarp_is_enabled_for_untrusted_interfaces',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_2_2_ensure_noproxyarp_is_enabled_for_untrusted_interfaces(commands, ref):
    assert '' in commands.chk_cmd, ref
