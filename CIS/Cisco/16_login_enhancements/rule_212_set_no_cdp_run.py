import pytest
from comfy.compliance import *

@medium(
  name = 'rule_212_set_no_cdp_run',
  platform = ['cisco_ios'],
  commands=dict(check_command='show  cdp')
)
def rule_212_set_no_cdp_run(configuration, commands, device):
    assert f'hostname#show  cdp' in commands.check_command,"\n# Remediation: hostname(config)#no cdp run  \n# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/cdp/command/cdp-cr-a1.html#GUID-E006FAC8-417E-4C3F-B732-4D47B0447750\n\n"
