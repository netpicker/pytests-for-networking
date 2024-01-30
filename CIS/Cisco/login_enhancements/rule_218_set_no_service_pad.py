import pytest
from comfy.compliance import *

@medium(
  name = 'rule_218_set_no_service_pad',
  platform = ['cisco_ios']
)
def rule_218_set_no_service_pad(configuration, commands, device):
    assert 'ncl service pad' in configuration

# Remediation: hostname(config)#no service pad  

# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/wan/command/wan-s1.html#GUID-C5497B77-3FD4-4D2F-AB08-1317D5F5473B
