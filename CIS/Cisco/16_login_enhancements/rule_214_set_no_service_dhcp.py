import pytest
from comfy.compliance import *

@medium(
  name = 'rule_214_set_no_service_dhcp',
  platform = ['cisco_ios']
)
def rule_214_set_no_service_dhcp(configuration, commands, device):
    assert 'dhcp' in configuration,"\n# Remediation: hostname(config)#<strong>no service dhcp</strong>  \n# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/ipaddr/command/ipaddr-r1.html#GUID-1516B259-AA28-4839-B968-8DDBF0B382F6\n\n"
