from comfy.compliance import medium
import re


@medium(
  name='rule_1211_set_exec_timeout_to_less_than_or_equal_to_10_min_on_ip_http',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_1211_set_exec_timeout_to_less_than_or_equal_to_10_min_on_ip_http(configuration, ref):
    if "no ip http" not in configuration:
        timeout_found = False
        for line in configuration:
            if "ip http timeout-policy idle" in line:
                match = re.search(r'ip http timeout-policy idle\s+(\d+)\s*life', line)
                if match:
                    timeout_found = True
                    seconds = int(match.group(1))
                    assert seconds < 600, ref
        if not timeout_found:
            assert False, ref
    else:
        assert True, ref
