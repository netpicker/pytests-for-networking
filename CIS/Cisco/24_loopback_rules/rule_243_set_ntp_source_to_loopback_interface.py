import pytest
from comfy.compliance import *

@low(
  name = 'rule_243_set_ntp_source_to_loopback_interface',
  platform = ['cisco_ios']
)
def rule_243_set_ntp_source_to_loopback_interface(configuration, commands, device):
    assert 'ntp source' in configuration,"\n# Remediation: hostname(config)#ntp source loopback {<em> loopback_interface_number}</em>  \n# References: \n\n"
