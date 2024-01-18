
import pytest
from comfy.compliance import Source, medium

@medium(
  name = rule_1211_set_exec_timeout_to_less_than_or_equal_to_10_min_on_ip,
  platform = ['cisco_ios']
)
def rule_1211_set_exec_timeout_to_less_than_or_equal_to_10_min_on_ip(configuration,commands,device):
    assert '' in configuration  

#Remediation: 

#References: 1. http://www.cisco.com/en/US/docs/ios -
