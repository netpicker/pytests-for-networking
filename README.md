# Network Automation Jobs for Netpicker

This repository contains example automation jobs designed for use within [Netpicker](https://netpicker.io/), our all-in-one network automation platform.

## Overview

Netpicker automation jobs are Python functions that leverage the power of [Netmiko](https://github.com/ktbyers/netmiko) to interact with network devices. You can define jobs to perform configuration changes, execute show commands, gather data, and integrate with Netpicker's workflow engine.

## Creating an Automation Job

To define an automation job, use the `@job` decorator from the `comfy.automate` library on a Python function.

### Example Job: Setting NTP Server on Juniper Devices

```python
from comfy.automate import job
import logging

# Target Juniper platforms (Junos) using Netmiko platform type wildcard
@job(platform='juniper_junos*')
def set_ntp_server_juniper_junos(device, ntp_server: str):
    """
    Configures the NTP server on a Juniper device and commits the change.

    Args:
        device: The Netpicker device object (contains IP, platform, etc.).
        ntp_server (str): The IP address or hostname of the NTP server.
    """
    logging.info(f"Starting NTP configuration job on device {device.ipaddress}")

    # Commands to send in configuration mode
    config_commands = [
      f"set system ntp server {ntp_server}",
      "commit" # Necessary for Junos to apply changes
    ]

    try:
        # device.cli provides access to Netmiko methods
        # send_config_set enters config mode, sends commands, and exits
        result = device.cli.send_config_set(config_commands)
        logging.info(f"Configuration successful: {result}")
        # Return the result for use in Netpicker workflows
        return result
    except Exception as e:
        logging.error(f"Error configuring NTP on {device.ipaddress}: {e}")
        # Optionally re-raise or return an error indicator
        raise

```

### The `@job` Decorator

- **`platform`**: Specifies the target device platform(s).
  - Accepts a string or a list of strings.
  - These strings correspond to [Netmiko platform types](https://github.com/ktbyers/netmiko/blob/develop/PLATFORMS.md). Examples: `'cisco_ios'`, `'arista_eos'`, `'juniper_junos'`.
  - You can use an asterisk (`*`) as a wildcard (e.g., `'cisco*'` matches `cisco_ios`, `cisco_xe`, `cisco_xr`, etc.).

### Function Arguments

- **`device`**: The first argument is always the Netpicker `device` object. It contains attributes like `name`, `ipaddress`, `platform`, `tags`, etc.
- **Custom Arguments**: Any subsequent arguments (like `ntp_server: str` in the example) are defined by you. These become parameters that must be provided when running the job via Netpicker.

## Interacting with Devices using Netmiko

Netpicker provides access to Netmiko's capabilities through the `device.cli` object.

### Configuration Changes (`send_config_set`)

- Use `device.cli.send_config_set([...])` to send configuration commands.
- **How it works:** Netmiko typically automatically enters configuration mode on the device, sends the list of commands you provide, and then exits configuration mode.
- **Important:** For many platforms (like Cisco IOS/NX-OS, Arista EOS), changes made in configuration mode are not saved automatically. You usually need to include a command like `'write memory'` or `'copy running-config startup-config'` in your command list if you want the changes to persist after a reboot.
- For platforms like Juniper Junos, a `'commit'` command is required within the configuration session to apply the changes, as shown in the example.
- **Reference:** [Netmiko `send_config_set` documentation](https://ktbyers.github.io/netmiko/docs/netmiko/index.html#netmiko.base_connection.BaseConnection.send_config_set)

### Show Commands (`send_command`)

- Use `device.cli.send_command("...")` to execute operational or show commands (e.g., `'show version'`, `'show interfaces'`).
- This method does _not_ enter configuration mode.
- The output of the command is returned as a string.
- **Reference:** [Netmiko `send_command` documentation](https://ktbyers.github.io/netmiko/docs/netmiko/index.html#netmiko.base_connection.BaseConnection.send_command)

### Netmiko Tips & Tricks

- **Error Handling:** Network operations can fail. Wrap `device.cli` calls in `try...except` blocks to catch potential Netmiko exceptions (e.g., timeouts, authentication errors) and log them appropriately.
- **Timeouts:** Be mindful of command execution time. Netmiko has default timeouts, but complex commands might take longer. While direct timeout adjustment might not be exposed via `device.cli`, structuring jobs efficiently helps. For long-running commands, consider alternative approaches if possible.
- **Platform Differences:** Always consult the Netmiko documentation and test thoroughly, as command syntax and behavior (especially regarding configuration saving) vary significantly between vendors and platforms.
- **Idempotency:** Design your configuration jobs to be idempotent where possible. This means running the job multiple times should result in the same final state without causing errors or unintended changes.

## Logging

- Use Python's standard `logging` module (`import logging`).
- Call `logging.info()`, `logging.warning()`, `logging.error()`, `logging.debug()` as needed.
- Logs are captured and visible within the Netpicker job execution details.

## Return Values

- You can `return` a value (like the `result` from `send_config_set` or `send_command`) from your job function.
- Returned values can be captured by Netpicker and used in subsequent steps within a workflow, enabling conditional logic or data passing.

---

_For more details on Netpicker, visit [netpicker.io](https://netpicker.io/)._
_For in-depth Netmiko information, refer to the [official Netmiko documentation](https://ktbyers.github.io/netmiko/docs/netmiko/)._
