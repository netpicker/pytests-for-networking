from comfy.compliance import medium


@medium(
    name='rule_143_set_username_secret_for_all_local_users',
    platform=['cisco_ios', 'cisco_xe']
)
def rule_143_set_username_secret_for_all_local_users(configuration, ref):
    for line in configuration:
        if 'username' in line:
            if 'secret' in line:
                return
            else:
                assert False, ref
