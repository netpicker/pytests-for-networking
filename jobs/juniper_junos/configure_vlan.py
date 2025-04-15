import logging
from comfy.automate import job


@job(platform='juniper_junos')
def configure_vlan(device, vlan_id: int, vlan_name: str):
    """
    Configures a VLAN on a Juniper Junos device.

    Args:
        device: The Netpicker device object.
        vlan_id (int): The ID of the VLAN to configure.
        vlan_name (str): The name to assign to the VLAN. This will also be used
                       as the VLAN identifier in Junos configuration.
    """
    log_prefix = (
        f"Device {device.ipaddress}, VLAN {vlan_name} (ID {vlan_id}):"
    )
    logging.info(f"{log_prefix} Starting VLAN configuration job.")

    # Junos configuration typically uses 'set' commands in configuration mode.
    # The vlan_name is often used as the key in the configuration hierarchy.
    config_commands = [
        f"set vlans {vlan_name} vlan-id {vlan_id}",
        "commit"
    ]

    try:
        # Send configuration commands
        config_result = device.cli.send_config_set(config_commands)
        logging.info(
            f"{log_prefix} Configuration commands sent. "
            f"Result: {config_result}"
        )

        return config_result
    except Exception as e:
        logging.error(
            f"{log_prefix} Error configuring VLAN: {e}"
        )
        raise
