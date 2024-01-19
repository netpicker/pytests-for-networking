import pytest
from comfy.compliance import *

@medium(
  name = rule_128_set_exec_timeout_to_less_than_or_equal_to_10_minutes_line,
  platform = ['cisco_ios']
)
def rule_128_set_exec_timeout_to_less_than_or_equal_to_10_minutes_line(configuration,commands,device):
    assert '' in configuration  

#Remediation: hostname(config)#line vty {line_number} [ending_line_number]  

#References: 
