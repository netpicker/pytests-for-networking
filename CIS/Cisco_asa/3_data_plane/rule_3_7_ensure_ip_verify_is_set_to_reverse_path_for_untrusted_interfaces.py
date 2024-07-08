from comfy.compliance import medium


@medium(
      name='rule_3_7_ensure_ip_verify_is_set_to_reverse_path_for_untrusted_interfaces',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_3_7_ensure_ip_verify_is_set_to_reverse_path_for_untrusted_interfaces(commands, ref):
    assert '' in commands.chk_cmd, ref
