import pytest
from comfy.compliance import *

@medium(
  name = 'rule_311_set_no_ip_source_route',
  platform = ['cisco_ios']
)
def rule_311_set_no_ip_source_route(configuration, commands, device):
    assert 'ip source-route' in configuration,"\n# Remediation: hostname(config)#no ip source-route \n# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/ipaddr/command/ipaddr-i4.html#GUID-C7F971DD-358F-4B43-9F3E-244F5D4A3A93\n\n
