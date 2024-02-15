from comfy.compliance import low


@low(
  name='rule_115_ensure_rogue_location_discovery_protocol_is_enabled',
  platform=['cisco_wlc'],
  commands=dict(chk_cmd='show rogue ap rldp summary')
)
def rule_115_ensure_rogue_location_discovery_protocol_is_enabled(commands):
    uri = (
        "http://www.cisco.com/en/US/docs/wireless/controller/7.0/command/reference/cli7"
        ""
    )

    remediation = (f"""
    Remediation: -

    References: {uri}

    """)

    assert 'show rogue ap rldp summary' in commands.chk_cmd, remediation
