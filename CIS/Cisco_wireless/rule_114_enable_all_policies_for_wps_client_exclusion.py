from comfy.compliance import low


@low(
    name='rule_114_enable_all_policies_for_wps_client_exclusion',
    platform=['cisco_wlc'],
    commands=dict(chk_cmd='show wps summary')
)
def rule_114_enable_all_policies_for_wps_client_exclusion(commands, ref):
    assert 'Disable' not in commands.chk_cmd, ref
