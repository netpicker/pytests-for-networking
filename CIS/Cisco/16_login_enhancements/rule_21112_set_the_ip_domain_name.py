import pytest
from comfy.compliance import *

@medium(
  name = 'rule_21112_set_the_ip_domain_name',
  platform = ['cisco_ios']
)
def rule_21112_set_the_ip_domain_name(configuration, commands, device):
    assert 'domain-name' in configuration,"\n# Remediation: \n# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/ipaddr/command/ipaddr-i3.html#GUID-A706D62B-9170-45CE-A2C2-7B2052BE2CAB\n\n"
