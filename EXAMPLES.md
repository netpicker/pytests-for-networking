<img src="https://netpicker.io/wp-content/uploads/2024/01/netpicker-logo-276x300.png" width="160">

# Compliance Examples

A set of common Netpicker compliance use-cases.

<br />

## Table of Contents

1. [Format of the Rules](#format-of-the-rules)
2. [Simple Examples](#simple-examples)
3. [Multiple Lines](#multiple-lines)
4. [Multiple Commands](#multiple-commands)
5. [Using Configuration and Commands](#configuration-commands)
6. [Using device parameters](#device-parameters)
7. [Using TextFSM](#using-textfsm)

## Format of the Rules

### Understand the Netpicker Rule Structure
- **Severity Levels**: Decide whether your rule should be low, medium, or high severity, depending on its importance.
- **Rule Naming**: Name your rule starting with `rule_`, followed by a descriptive name that reflects the test's purpose.
- **Platform Specification**: Identify the platforms (e.g., `cisco_ios`, `juniper`) the rule applies to.

### Write the Netpicker Rule
- **Basic Structure**: Use the Netpicker rule template:
  ```python
  @low(
     name='rule_name',
     platform=['platform_name'],
  )
  def rule_name(configuration):
      assert 'keyword' in configuration
  ```
- **Customize the Rule**:
  - Replace `'rule_name'` with your actual rule name.
  - Specify the correct platform(s).
  - Implement the logic inside the function, using assertions to determine if the device complies with the rule.

## Simple Examples

### Example 1: Check for Specific Banner Text
This rule ensures that a Cisco IOS device has the correct banner text configured:

```python
@low(
   name='rule_banner_check',
   platform=['cisco_ios'],
)
def rule_banner_check(configuration):
    assert 'Authorized access only' in configuration
```
*This example checks if the banner contains the text "Authorized access only".*

### Example 2: Ensure NTP is Synchronized
This rule checks the status of NTP synchronization and reports if the device is not in sync:

```python
@medium(
   name='rule_ntp_sync',
   platform=['cisco_ios'],
   commands=dict(show_ntp_status: 'show ntp status'),
)
def rule_ntp_sync(commands):
    assert ' synchronized' in configuration
```
*This example executes the show ntp status command and checks if the output contains the word " synchronized." If the NTP status is not synchronized, the rule will fail, indicating that the device is not in sync with the NTP server.ecure manner.*

## Multiple Lines

### Example: Ensure Specific Log Servers are Configured
This rule checks that specific log servers are configured in the device:

```python
@medium(
   name='rule_specific_log_servers_configured',
   platform=['cisco_ios'],
)
def rule_specific_log_servers_configured(configuration):
    assert "logging host 1.2.3.4" in configuration, "Log server 1.2.3.4 is not configured"
    assert "logging host 2.3.4.5" in configuration, "Log server 2.3.4.5 is not configured"
```
*This rule ensures that the device configuration includes the specific log servers 1.2.3.4 and 2.3.4.5. If either line is missing, the rule will fail and report which log server is not configured.*