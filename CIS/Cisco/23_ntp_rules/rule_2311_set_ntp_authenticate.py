import pytest
from comfy.compliance import *

@low(
  name = 'rule_2311_set_ntp_authenticate',
  platform = ['cisco_ios']
)
def rule_2311_set_ntp_authenticate(configuration, commands, device):
    assert 'ntp' in configuration,"\n# Remediation: hostname(config)#ntp authenticate  \n# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/bsm/command/bsm-cr-n1.html#GUID-8BEBDAF4-6D03-4C3E-B8D6-6BCBC7D0F324\n\n"
