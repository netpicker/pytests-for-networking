import pytest
from comfy.compliance import *

@low(
  name = 'rule_2313_set_the_ntp_trusted_key',
  platform = ['cisco_ios']
)
def rule_2313_set_the_ntp_trusted_key(configuration, commands, device):
    assert 'ntp trusted-key' in configuration,"\n# Remediation: \n# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/bsm/command/bsm-cr-n1.html#GUID-89CA798D-0F12-4AE8-B382-DE10CBD261DB\n\n"
