import logging
from comfy.automate import job


@job(platform='cisco_nxos')
def configure_vlan(device, vlan_id: int, vlan_name: str):
    """
    Configures a VLAN on a Cisco NX-OS device.

    Args:
        device: The Netpicker device object.
        vlan_id (int): The ID of the VLAN to configure.
        vlan_name (str): The name to assign to the VLAN.
    """
    log_prefix = (
        f"Device {device.ipaddress}, VLAN {vlan_id}:"
    )
    logging.info(f"{log_prefix} Starting VLAN configuration job.")

    config_commands = [
        f"vlan {vlan_id}",
        f"name {vlan_name}"
        # Note: NX-OS typically applies VLAN changes immediately.
        # 'copy running-config startup-config' could be added here
        # if persistence across reboots is explicitly required by the workflow.
    ]

    try:
        result = device.cli.send_config_set(config_commands)
        logging.info(
            f"{log_prefix} Configuration successful. Result: {result}"
        )
        return result
    except Exception as e:
        logging.error(
            f"{log_prefix} Error configuring VLAN: {e}"
        )
        raise
