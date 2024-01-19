import pytest
from comfy.compliance import *

@low(
  name = rule_244_set_ip_tftp_source_interface_to_the_loopback_interface,
  platform = ['cisco_ios']
)
def rule_244_set_ip_tftp_source_interface_to_the_loopback_interface(configuration,commands,device):
    assert '' in configuration  

#Remediation: hostname(config)#ip tftp source -interface loopback 

#References: 1. http://www.cisco.com/en/US/docs/ios -
