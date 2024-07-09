from comfy.compliance import medium


@medium(
      name='rule_3_3_ensure_packet_fragments_are_restricted_for_untrusted_interfaces',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_3_3_ensure_packet_fragments_are_restricted_for_untrusted_interfaces(commands, ref):
    assert '' in commands.chk_cmd, ref
