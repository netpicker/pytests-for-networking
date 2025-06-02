from comfy import high


@high(
    name='rule_cve202220821',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version',
        check_redis='show processes | include redis',
        check_port='show processes | include 6379'
    ),
)
def rule_cve202220821(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2022-20821 vulnerability in Cisco IOS XR Software.
    The vulnerability is due to the health check RPM opening TCP port 6379 by default upon activation.
    An unauthenticated, remote attacker could exploit this vulnerability by connecting to the Redis
    instance on the open port, allowing them to write to the Redis in-memory database, write arbitrary
    files to the container filesystem, and retrieve information about the Redis database.
    """
    # Extract the output of the commands
    redis_output = commands.check_redis
    port_output = commands.check_port

    # Check if Redis is running and port 6379 is open
    redis_running = 'redis' in redis_output
    port_open = '6379' in port_output

    # Device is vulnerable if Redis is running and port 6379 is open
    is_vulnerable = redis_running and port_open

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2022-20821. "
        "The device has Redis running with port 6379 open, "
        "which could allow an unauthenticated attacker to access and modify the Redis database. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-redis-ABJyE5xK"
    )
