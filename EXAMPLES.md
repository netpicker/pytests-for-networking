<img src="https://netpicker.io/wp-content/uploads/2024/01/netpicker-logo-276x300.png" width="160">

# Compliance Examples

A set of common Netpicker compliance use-cases.

<br />

## Table of Contents

1. [Format of the Rules](#format-of-the-rules)
2. [Simple Examples](#simple-examples)
3. [Multiple Lines](#multiple-lines)
4. [Using Configuration and Commands](#using-configuration-and-commands)
5. [Using TextFSM](#using-textfsm)
6. [Using Tags for Device Grouping](#using-tags-for-device-grouping)
7. [Accessing Netbox Data in Netpicker Rules](#accessing-netbox-data-in-netpicker-rules)

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
   commands=dict(show_ntp_status='show ntp status'),
)
def rule_ntp_sync(commands):
    assert ' synchronized' in commands.show_ntp_status, "NTP is not synchronized"
```
*This example executes the show ntp status command and checks if the output contains the word " synchronized." If the NTP status is not synchronized, the rule will fail, indicating that the device is not in sync with the NTP server.ecure manner.*

## Multiple Lines

### Example 1: Ensure Specific Log Servers are Configured
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

### Example 2: Ensure All BGP Neighbors Are Up
This rule checks the status of BGP neighbors and reports if any neighbor is down:

```python
@medium(
   name='rule_bgp_neighbors_up',
   platform=['cisco_ios'],
   commands=dict('show_bgp_summary'='show ip bgp summary'),
)
def rule_bgp_neighbors_up(commands):
    bgp_output = commands.show_bgp_summary
    neighbors_down = [line for line in bgp_output.splitlines() if 'Idle' in line or 'Active' in line or 'Connect' in line]
    assert len(neighbors_down) == 0, f"BGP neighbors down: {', '.join([line.split()[0] for line in neighbors_down])}"
```
*This example executes the `show ip bgp summary` command and checks the status of all BGP neighbors. If any neighbor is in an "Idle," "Active," or "Connect" state, the rule will fail, listing the IP addresses of the down neighbors.*

## Using Configuration and Commands

### Example: Conditional BGP Neighbor Status Check

This rule first verifies whether BGP is configured on a Cisco IOS device. If BGP is configured, then it checks the status of BGP neighbors and reports if any neighbor is down.

```python
@medium(
    name='rule_bgp_neighbors_status',
    platform=['cisco_ios'],
)
def rule_bgp_neighbors_status(configuration, device):
    if "router bgp" in configuration:
        bgp_output = device.cli("show ip bgp summary")
        neighbors_down = [line for line in bgp_output.splitlines() if 'Idle' in line or 'Active' in line or 'Connect' in line]
        assert len(neighbors_down) == 0, f"BGP neighbors down: {', '.join([line.split()[0] for line in neighbors_down])}"
```
*This example looks for 'router bgp' in configuration and if found then executes the `show ip bgp summary` command and checks the status of all BGP neighbors. If any neighbor is in an "Idle," "Active," or "Connect" state, the rule will fail, listing the IP addresses of the down neighbors.*

## Using TextFSM

### Example: Interface Status Check Using TextFSM

This rule checks the status of a specific interface on a Cisco IOS device using TextFSM for command output parsing. It ensures that the interface is up and running.

```python
@medium(
    name='rule_interface_status_check',
    platform=['cisco_ios'],
)
def rule_interface_status_check(device):
    # Execute the command to get interface details using TextFSM parsing
    inf_output = device.cli("show interface eth0/0").fsm[0]
    
    # Print the parsed output for debugging or verification purposes
    print(inf_output)
    
    # Assert that the interface is up; fail the test if it is down
    assert inf_output.link_status == "up", "Interface is down"
```
*This example uses TextFSM to parse the output of the `show interface eth0/0` command. The rule then checks the parsed output to verify that the interface is up. If the interface is down, the rule will fail, reporting the issue.* 

## Using Tags for Device Grouping
You can create tags such as `datacenter`, `campus`, or `branch`, and then apply specific rules to all devices in these groups.

### Example: Printing All Devices with a Specific Tag

In this example, the `device_tags` parameter is set to `campus`, meaning the rule is intended to apply only to devices tagged as part of the `campus` group.

```python
@medium(
    name='rule_one',
    platform=['cisco_ios'],  # Specify the platform as usual
    device_tags='campus',    # This rule will apply to devices tagged with 'campus'
)
def rule_one(devices, device):
    # Iterate over all devices and print the details of those with the 'campus' tag
    for dev in devices:
        if 'campus' in dev.tags:
            print(f"Device: {dev.name} and IP address: {dev.ipaddress}")
```
*This example demonstrates how to print the name and IP address of all devices tagged with `campus`.*

## Accessing NetBox Data in Netpicker Rules

Netpicker allows you to integrate with NetBox, a popular open-source IP address management (IPAM) and data center infrastructure management (DCIM) tool. By accessing NetBox data within your Netpicker rules, you can enhance your network automation tasks by incorporating detailed device information directly from your source of truth.

### Example: Accessing and Printing Device Names from NetBox
```python
@medium(
    name='rule_netbox',
)
def rule_netbox(netbox):
    # Fetch all devices from NetBox
    devices = netbox.dcim.devices.all()
    
    # Extract the names of the devices
    device_names = [device.name for device in devices]

    # Print the names of all devices fetched from NetBox
    for name in device_names:
        print(name)
```
*The above example demonstrates how to access NetBox data within a Netpicker rule. This rule fetches all devices from NetBox and prints their names.*
