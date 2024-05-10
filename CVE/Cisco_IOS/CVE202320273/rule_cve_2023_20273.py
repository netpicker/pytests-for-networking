from comfy.compliance import medium


@medium(
    name='rule_cve202320273',
    platform=['cisco_xe'],
    commands=dict(version='show version | include RELEASE SOFTWARE')
)
def rule_cve202320273(commands):
    import re
    pattern = r"Version\s([0-9.]+)"
    match = re.search(pattern, str(commands.version))
    s_version = match.group(1)
    if not s_version:
        assert "No version retrieved, when in doubt always not compliant"
    if s_version.startswith('16.12.'):
        version = tuple(map(int, s_version.split('.')))
        assert version < (16, 12, 0) or version > (16, 12, 10)
    if s_version.startswith('17.3.'):
        version = tuple(map(int, s_version.split('.')))
        assert version < (17, 3, 0) or version > (17, 3, 8)
    if s_version.startswith('17.6.'):
        version = tuple(map(int, s_version.split('.')))
        assert version < (17, 6, 0) or version > (17, 6, 6)
    if s_version.startswith('17.9.'):
        version = tuple(map(int, s_version.split('.')))
        assert version < (17, 9, 0) or version > (17, 9, 4)
