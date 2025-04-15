import logging
from comfy.automate import job


@job(platform='cisco_ios')
def configure_vlan(device, vlan_id: int, vlan_name: str,
                   save_config: bool = True):
    """
    Configures a VLAN with a specific name on a Cisco IOS device.

    Optionally saves the running configuration to the startup configuration.

    Args:
        device: The Netpicker device object (contains IP, platform, etc.).
        vlan_id (int): The ID of the VLAN to configure (e.g., 100).
        vlan_name (str): The name to assign to the VLAN (e.g., 'DATA').
        save_config (bool): If True (default), saves the running-config.
    """
    log_prefix = f"Device {device.ipaddress} VLAN {vlan_id}:"
    logging.info(f"{log_prefix} Starting VLAN configuration job.")

    # Commands to send in configuration mode
    config_commands = [
        f"vlan {vlan_id}",
        f"name {vlan_name}"
    ]

    # Command to save the configuration
    save_command = "copy running-config startup-config"

    try:
        # Send the primary configuration commands
        result = device.cli.send_config_set(config_commands)
        logging.info(f"{log_prefix} VLAN configuration commands sent "
                     f"successfully.")
        logging.debug(f"{log_prefix} Config result: {result}")

        if save_config:
            # Execute the save command outside of config mode.
            # Netmiko's send_command handles prompts like filename confirmation
            # We might need send_command_timing for very slow saves.
            logging.info(f"{log_prefix} Attempting to save configuration.")
            # Send command and expect the confirm prompt
            save_result = device.cli.send_command(
                save_command, expect_string=r'\[confirm\]'
            )
            # Send newline to confirm the default filename prompt,
            # expecting the standard IOS prompt (#)
            save_result_confirm = device.cli.send_command(
                '\n', expect_string=r'#'
            )
            save_result += save_result_confirm

            logging.info(f"{log_prefix} Save configuration successful.")
            logging.debug(f"{log_prefix} Save result: {save_result}")
            # Combine results for workflow output
            result += "\n--- Save Operation ---\n" + save_result
        else:
            logging.info(f"{log_prefix} Skipping configuration save.")

        # Return the combined result for use in Netpicker workflows
        return result
    except Exception as e:
        logging.error(f"{log_prefix} Error during VLAN configuration: {e}")
        # Re-raise the exception to signal failure in Netpicker
        raise
