from comfy.compliance import medium


@medium(
    name='rule_2112_set_version_2_for_ip_ssh_version',
    platform=['cisco_ios', 'cisco_xe'],
    commands=dict(chk_cmd='sh ip ssh')
)
def rule_2112_set_version_2_for_ip_ssh_version(commands, ref):
    assert 'SSH Enabled - version 2.0' in commands.chk_cmd, ref
