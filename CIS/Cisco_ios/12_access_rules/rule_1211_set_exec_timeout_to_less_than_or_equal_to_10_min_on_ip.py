from comfy.compliance import medium


@medium(
  name='rule_1211_set_exec_timeout_to_less_than_or_equal_to_10_min_on_ip',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_1211_set_exec_timeout_to_less_than_or_equal_to_10_min_on_ip(configuration):
    uri = (
        "http://www.cisco.com/en/US/docs/ios-xml/ios/fundamentals/command/D_through_E.html#GUID-768"
        "05E6F-9E89-4457-A9DC-5944C8FE5419"
    )

    remediation = (f"""
    Remediation: ip http timeout-policy idle 600 life <nnnn> requests <nn>

    References: {uri}

    """)
    if "no ip http" not in configuration:
        timeout_found = False
        for line in configuration:
            if "ip http timeout-policy idle" in line:
                match = re.search(r'ip http timeout-policy idle\s+(\d+)\s*life', line)
                if match:
                    timeout_found = True
                    seconds = int(match.group(1))
                    assert seconds < 600, remediation
        if not timeout_found:
            assert False, remediation
    else:
        assert True, remeidation


