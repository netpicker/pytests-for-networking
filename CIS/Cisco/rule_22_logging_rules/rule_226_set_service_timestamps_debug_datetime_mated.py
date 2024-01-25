import pytest
from comfy.compliance import *

@medium(
  name = 'rule_226_set_service_timestamps_debug_datetime_mated',
  platform = ['cisco_ios']
)
def rule_226_set_service_timestamps_debug_datetime_mated(configuration,commands,device):
    assert '' in configuration  

#Remediation: hostname(config)#service timestamps debug datetime {<em>msec</em>} show -

#References: 1. http://www.cisco.com/en/US/docs/ios -
