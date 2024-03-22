import re
from comfy.compliance import medium


@medium(
    name='rule_126_set_exec_timeout_to_less_than_or_equal_to_10_minutes_for',
    platform=['cisco_ios', 'cisco_xe'],
    commands=dict(chk_cmd='sh run | sec line aux 0')
)
def rule_126_set_exec_timeout_to_less_than_or_equal_to_10_minutes_for(commands, ref):
    timeout_found = False
    for line in commands.chk_cmd:
        if "exec-timeout" in line:
            match = re.search(r'exec-timeout\s+(\d+)\s*(\d*)', line)
            if match:
                timeout_found = True
                minutes = int(match.group(1))
                seconds = int(match.group(2)) if match.group(2) else 0
                assert minutes < 10 or (minutes == 10 and seconds == 0), ref
    if not timeout_found:
        assert False, ref
