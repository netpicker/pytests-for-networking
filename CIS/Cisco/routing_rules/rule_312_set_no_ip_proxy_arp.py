import pytest
from comfy.compliance import *

@low(
  name = 'rule_312_set_no_ip_proxy_arp',
  platform = ['cisco_ios']
)
def rule_312_set_no_ip_proxy_arp(configuration, commands, device):
    assert '' in configuration

# Remediation: hostname(config)#interface {interface}  

# References: 1. http://www.cisco.com/en/US/docs/ios -xml/ios/ipaddr/comm and/ipaddr -
