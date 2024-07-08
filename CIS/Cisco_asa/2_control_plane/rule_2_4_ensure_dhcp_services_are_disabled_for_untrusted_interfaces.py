from comfy.compliance import medium


@medium(
      name='rule_2_4_ensure_dhcp_services_are_disabled_for_untrusted_interfaces',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_2_4_ensure_dhcp_services_are_disabled_for_untrusted_interfaces(commands, ref):
    assert '' in commands.chk_cmd, ref
