import logging
import re
from comfy.automate import job

@job(platform='cisco*')
def ensure_acl_bound(device, interface: str, acl_name: str, direction: str = "in"):
    """
    Ensures an ACL is applied on a given interface in the specified direction.

    Args:
        device: The Netpicker device object.
        interface (str): Interface name (e.g., GigabitEthernet0/1).
        acl_name (str): Name of the ACL to bind.
        direction (str): Direction to apply the ACL ('in' or 'out').
    """
    log_prefix = f"Device {device.ipaddress}, Interface {interface}:"
    logging.info(f"{log_prefix} Ensuring ACL '{acl_name}' is applied {direction}...")

    try:
        # Step 1: Get interface config
        config = device.cli.send_command(f"show running-config interface {interface}")
        logging.debug(f"{log_prefix} Interface config:\n{config}")

        # Step 2: Check if ACL is already bound
        acl_line = f"ip access-group {acl_name} {direction}"
        already_bound = acl_line in config

        if already_bound:
            logging.info(f"{log_prefix} ACL already bound. No changes needed.")
            return {"status": "exists", "interface": interface, "acl": acl_name, "direction": direction}

        # Step 3: Apply ACL binding
        config_commands = [
            f"interface {interface}",
            acl_line
        ]

        if device.platform == "cisco_nxos":
            config_commands.append("copy running-config startup-config")
        else:
            config_commands.append("write memory")

        result = device.cli.send_config_set(config_commands)
        logging.info(f"{log_prefix} ACL bound successfully.")
        return {
            "status": "bound",
            "interface": interface,
            "acl": acl_name,
            "direction": direction,
            "output": result
        }

    except Exception as e:
        logging.error(f"{log_prefix} Error applying ACL: {e}")
        raise
