from comfy.compliance import medium


@medium(
    name='rule_16_disable_management_via_wireless_interface',
    platform=['cisco_wlc'],
    commands=dict(chk_cmd='show network summary')
)
def rule_16_disable_management_via_wireless_interface(commands, ref):
    assert 'Mgmt Via Wireless Interface................. Disable' in commands.chk_cmd, ref
