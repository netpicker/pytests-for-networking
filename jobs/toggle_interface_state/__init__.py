import logging
from comfy.automate import job

@job(platform='cisco*')
def toggle_interface_state(device, interface: str, shutdown: bool = True):
    """
    Enables or disables a network interface on Cisco IOS / NX-OS devices.

    Args:
        device: The Netpicker device object.
        interface (str): The interface name (e.g., 'GigabitEthernet0/1').
        shutdown (bool): Whether to shut down (True) or enable (False) the interface.
    """
    log_prefix = f"Device {device.ipaddress}, Interface {interface}:"
    logging.info(f"{log_prefix} Toggling interface state to {'shutdown' if shutdown else 'no shutdown'}.")

    config_commands = [
        f"interface {interface}",
        "shutdown" if shutdown else "no shutdown"
    ]

    try:
        result = device.cli.send_config_set(config_commands)
        logging.info(f"{log_prefix} Interface state changed successfully.")
        logging.debug(f"{log_prefix} Output: {result}")
        return result
    except Exception as e:
        logging.error(f"{log_prefix} Error changing interface state: {e}")
        raise
