import pytest
from comfy.compliance import *

@low(
  name = 'rule_312_set_no_ip_proxy_arp',
  platform = ['cisco_ios'],
  commands=dict(check_command='sh ip int {<em>interface</em>} | incl proxy-arp')
)
def rule_312_set_no_ip_proxy_arp(configuration, commands, device):
    assert f' proxy-arp' in commands.check_command,"\n# Remediation: hostname(config)#interface {interface}  \n# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/ipaddr/command/ipaddr-i4.html#GUID-AEB7DDCB-7B3D-4036-ACF0-0A0250F3002E\n\n
