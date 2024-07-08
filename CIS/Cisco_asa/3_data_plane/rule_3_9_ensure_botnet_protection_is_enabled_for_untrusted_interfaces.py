from comfy.compliance import low


@low(
      name='rule_3_9_ensure_botnet_protection_is_enabled_for_untrusted_interfaces',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_3_9_ensure_botnet_protection_is_enabled_for_untrusted_interfaces(commands, ref):
    assert '' in commands.chk_cmd, ref
