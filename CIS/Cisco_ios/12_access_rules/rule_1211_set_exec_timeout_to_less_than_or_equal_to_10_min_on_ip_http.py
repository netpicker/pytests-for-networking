from comfy.compliance import medium


@medium(
  name='rule_1211_set_exec_timeout_to_less_than_or_equal_to_10_min_on_ip',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_1211_set_exec_timeout_to_less_than_or_equal_to_10_min_on_ip(configuration,ref):
    if "no ip http" not in configuration:
        timeout_found = False
        for line in configuration:
            if "ip http timeout-policy idle" in line:
                match = re.search(r'ip http timeout-policy idle\s+(\d+)\s*life', line)
                if match:
                    timeout_found = True
                    seconds = int(match.group(1))
                    assert seconds < 600, remediation,ref
        if not timeout_found:
            assert False, remediation,ref
    else:
        assert True, remeidation,ref


