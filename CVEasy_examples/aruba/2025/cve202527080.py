from comfy import high


@high(
    name='rule_cve202527080',
    platform=['aruba_aoscx'],
    commands=dict(
        show_version='show version',
        show_running_config='show running-config',
    ),
)
def rule_cve202527080(configuration, commands, device, devices):
    """
    CVE-2025-27080 - Authenticated Sensitive Information Disclosure in AOS-CX CLI

    Advisory: HPESBNW04818 rev.1 (2025-03-18)
    Vulnerable versions (per advisory):
      - AOS-CX 10.15.xxxx: 10.15.1000 and below
      - AOS-CX 10.14.xxxx: 10.14.1030 and below
      - AOS-CX 10.13.xxxx: 10.13.1070 and below
      - AOS-CX 10.10.xxxx: 10.10.1140 and below

    Workaround guidance (per advisory):
      - Use secure-prompt or ciphertext configuration options when entering sensitive information.
      - Change any secret keys/passwords previously entered in plain text.

    This rule flags devices that are:
      (1) running a vulnerable AOS-CX version AND
      (2) appear to allow/contain plaintext secrets in configuration (i.e., not using secure-prompt/ciphertext).
    """
    advisory_url = "https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw04818en_us"

    version_output = (commands.show_version or "").strip()
    running_config = (commands.show_running_config or "").lower()

    def _parse_aoscx_version(text: str):
        """
        Extracts the first occurrence of an AOS-CX version like 10.14.1030 from 'show version' output.
        """
        import re

        m = re.search(r"\b(\d+)\.(\d+)\.(\d+)\b", text)
        if not m:
            return None
        return int(m.group(1)), int(m.group(2)), int(m.group(3))

    def _is_vulnerable_version(ver):
        if not ver:
            return False
        major, minor, patch = ver

        # Only branches listed in advisory
        if major != 10:
            return False

        if minor == 15:
            return patch <= 1000
        if minor == 14:
            return patch <= 1030
        if minor == 13:
            return patch <= 1070
        if minor == 10:
            return patch <= 1140

        return False

    ver = _parse_aoscx_version(version_output)
    version_vulnerable = _is_vulnerable_version(ver)

    if not version_vulnerable:
        return

    # Heuristic configuration check:
    # Consider "safe" if config indicates use of secure-prompt or ciphertext options.
    # Consider "vulnerable" if we see likely plaintext secrets (e.g., "password " or "secret ")
    # and we do NOT see secure-prompt/ciphertext indicators.
    has_secure_prompt = "secure-prompt" in running_config
    has_ciphertext = "ciphertext" in running_config

    # Common plaintext indicators across network device configs (heuristic)
    plaintext_indicators = [
        "password ",
        "secret ",
        "community ",
        "snmp-server community",
        "radius-server host",
        "tacacs-server host",
        "ldap bind-password",
        "client-secret",
        "shared-key",
        "pre-shared-key",
        "psk ",
        "wpa-passphrase",
        "private-key",
        "api-token",
        "token ",
    ]
    has_plaintext_like_secrets = any(ind in running_config for ind in plaintext_indicators)

    config_vulnerable = (has_plaintext_like_secrets and not (has_secure_prompt or has_ciphertext))

    assert not config_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-27080 (AOS-CX CLI sensitive information disclosure). "
        f"Detected vulnerable AOS-CX version from 'show version' output ({version_output!r}) and configuration "
        f"appears to include plaintext-like secrets without 'secure-prompt' or 'ciphertext' protections. "
        f"Upgrade to a fixed release (10.15.1001+, 10.14.1040+, 10.13.1080+, 10.10.1150+) and re-enter/rotate "
        f"any secrets using secure-prompt/ciphertext as recommended. Advisory: {advisory_url}"
    )