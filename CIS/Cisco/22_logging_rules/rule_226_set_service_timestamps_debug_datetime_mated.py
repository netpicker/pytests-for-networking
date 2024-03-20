from comfy.compliance import medium

uri = (
    "http://www.cisco.com/en/US/docs/ios-xml/ios/fundamentals/command/R_through_setup.html#GUID-DC1"
    "10E59-D294-4E3D-B67F-CCB06E607FC6"
)

remediation = (f"""
    Remediation: hostname(config)#service timestamps debug datetime {{<em>msec</em>}} show -

    References: {uri}

    """)


@medium(
  name='rule_226_set_service_timestamps_debug_datetime_mated',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_226_set_service_timestamps_debug_datetime_mated(configuration):
    assert 'service timestamps' in configuration, remediation
