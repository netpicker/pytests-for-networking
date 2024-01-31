import pytest
from comfy.compliance import *

@medium(
  name = 'rule_223_set_logging_console_critical',
  platform = ['cisco_ios']
)
def rule_223_set_logging_console_critical(configuration, commands, device):
    assert 'logging console' in configuration,"
# Remediation: hostname(config)#logging console critical  
# References: 


