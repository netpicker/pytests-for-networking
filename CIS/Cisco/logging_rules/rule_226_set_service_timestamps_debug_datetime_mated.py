import pytest
from comfy.compliance import *

@medium(
  name = 'rule_226_set_service_timestamps_debug_datetime_mated',
  platform = ['cisco_ios']
)
def rule_226_set_service_timestamps_debug_datetime_mated(configuration, commands, device):
    assert 'hostname#sh run | incl service timestamps' in configuration

# Remediation: hostname(config)#service timestamps debug datetime {<em>msec</em>} show -

# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/fundamentals/command/R_through_setup.html#GUID-DC110E59-D294-4E3D-B67F-CCB06E607FC6
