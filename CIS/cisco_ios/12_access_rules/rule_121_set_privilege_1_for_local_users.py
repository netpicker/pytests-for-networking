from comfy.compliance import medium


@medium(
    name='rule_121_set_privilege_1_for_local_users',
    platform=['cisco_ios', 'cisco_xe']
)
def rule_121_set_privilege_1_for_local_users(configuration, ref):
    assert 'privilege 1' in configuration, ref
