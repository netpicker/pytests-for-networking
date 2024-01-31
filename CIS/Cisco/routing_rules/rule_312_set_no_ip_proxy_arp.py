import pytest
from comfy.compliance import *

@low(
  name = 'rule_312_set_no_ip_proxy_arp',
  platform = ['cisco_ios'],
  commands=dict(check_command=hostname#sh ip int {<em>interface</em>} | incl proxy-arp)
)
def rule_312_set_no_ip_proxy_arp(configuration, commands, device):
    assert ' proxy-arp' in configuration

# Remediation: hostname(config)#interface {interface}  

# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/ipaddr/command/ipaddr-i4.html#GUID-AEB7DDCB-7B3D-4036-ACF0-0A0250F3002E
