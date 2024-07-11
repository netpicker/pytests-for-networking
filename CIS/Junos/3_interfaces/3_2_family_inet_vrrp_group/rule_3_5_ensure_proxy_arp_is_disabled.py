from comfy.compliance import low


@low(
      name='rule_3_5_ensure_proxy_arp_is_disabled',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_3_5_ensure_proxy_arp_is_disabled(commands, ref):
    assert '' in commands.chk_cmd, ref
