from comfy.compliance import medium


@medium(
      name='rule_2_5_ensure_icmp_is_restricted_for_untrusted_interfaces',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_2_5_ensure_icmp_is_restricted_for_untrusted_interfaces(commands, ref):
    assert '' in commands.chk_cmd, ref
