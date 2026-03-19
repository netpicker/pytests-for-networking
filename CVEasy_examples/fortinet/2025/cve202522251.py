from comfy import high


@high(
    name="rule_cve202522251",
    platform=["fortinet_fortinet"],
    commands=dict(
        show_version="get system status",
        show_fgsp="show system ha",
        show_local_in="show firewall local-in-policy",
        show_custom_services="show firewall service custom",
        show_addrgrp="show firewall addrgrp",
    ),
)
def rule_cve202522251(configuration, commands, device, devices):
    """
    CVE-2025-22251 (Fortinet FortiOS) - Firewall session injection in FGSP via crafted session sync packets (CWE-923).

    Summary (Fortinet PSIRT, 2025-06-10):
      - Improper restriction of communication channel to intended endpoints in FortiOS FGSP session synchronization.
      - May allow an unauthenticated attacker to inject unauthorized sessions via crafted FGSP session synchronization packets.

    Affected versions (per advisory):
      - FortiOS 7.6: 7.6.0 (fixed in 7.6.1+)
      - FortiOS 7.4: 7.4.0 through 7.4.5 (fixed in 7.4.6+)
      - FortiOS 7.2: all versions (migrate to a fixed release)
      - FortiOS 7.0: all versions (migrate to a fixed release)
      - FortiOS 6.4: all versions (migrate to a fixed release)

    Vulnerable configuration (exposure heuristic):
      - Device runs an affected FortiOS version, AND
      - FGSP is enabled/configured (session synchronization), AND
      - UDP/708 (FGSP) is not restricted to intended peers via local-in policy on the FGSP sync interface.

    Non-vulnerable scenarios:
      - FortiOS version is not affected (>= fixed version for 7.6/7.4, or not in affected trains), OR
      - Version cannot be parsed (rule returns safe), OR
      - FGSP is not enabled/configured, OR
      - Local-in policy restricts UDP/708 to allowed peer IPs (workaround applied).

    Advisory:
      - https://www.fortiguard.com/psirt/FG-IR-24-287
    """
    version_text = commands.show_version or ""
    ha_text = (commands.show_fgsp or "").lower()
    local_in_text = (commands.show_local_in or "").lower()
    svc_text = (commands.show_custom_services or "").lower()
    addrgrp_text = (commands.show_addrgrp or "").lower()

    def _parse_version(text: str):
        """
        FortiOS version formats commonly seen:
          - "FortiOS v7.4.5,build...."
          - "Version: 7.4.5"
        Return (major, minor, patch) or None.
        """
        import re

        patterns = [
            r"\bversion:\s*([0-9]+)\.([0-9]+)\.([0-9]+)\b",
            r"\bfortios\s+v([0-9]+)\.([0-9]+)\.([0-9]+)\b",
            r"\bv([0-9]+)\.([0-9]+)\.([0-9]+)\b",
        ]
        for pat in patterns:
            m = re.search(pat, text, re.IGNORECASE)
            if m:
                return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
        return None

    def _is_version_vulnerable(text: str):
        """
        Release-train-based matching only for trains explicitly listed as affected.
        Return (is_vuln: bool, parsed_version: tuple|None, rationale: str).
        If version cannot be parsed, return safe (False).
        """
        v = _parse_version(text)
        if not v:
            return (False, None, "version_unparsed_treated_safe")

        train = (v[0], v[1])

        # For trains with a known fixed version, vulnerable if v < fixed.
        fixed_by_train = {
            (7, 6): (7, 6, 1),  # 7.6.0 fixed in 7.6.1
            (7, 4): (7, 4, 6),  # 7.4.0-7.4.5 fixed in 7.4.6
        }

        if train in fixed_by_train:
            fix = fixed_by_train[train]
            return (v < fix, v, f"fixed_in_{fix[0]}.{fix[1]}.{fix[2]}")
        # "all versions" affected trains (no fixed version specified in advisory)
        if train in {(7, 2), (7, 0), (6, 4)}:
            return (True, v, "all_versions_affected_per_advisory")

        # Other trains not listed as affected => safe
        return (False, v, "train_not_listed_as_affected")

    def _fgsp_enabled(text_lower: str):
        """
        Heuristic: FGSP is configured if we see session-pickup enabled or explicit session-sync config.
        Common indicators in 'show system ha' output:
          - set session-pickup enable
          - set session-pickup-connectionless enable
          - set session-sync-dev <...>
          - set session-sync-interface <...>
        """
        indicators = (
            "set session-pickup enable",
            "set session-pickup-connectionless enable",
            "set session-sync-dev",
            "set session-sync-interface",
            "set standalone-config-sync enable",
        )
        return any(i in text_lower for i in indicators)

    def _fgsp_port_708_restricted(local_in_lower: str, svc_lower: str, addrgrp_lower: str):
        """
        Workaround guidance: local-in policies restricting UDP/708 only on FGSP session sync interface and to peers IPs.
        We treat as "restricted" if we can find evidence of:
          - a local-in-policy that ACCEPTs service FGSP (or UDP/708) from a peer addrgrp/address, AND
          - a subsequent DENY for the same service (or UDP/708) from all/any.
        This is a heuristic; absence => treat as not restricted.
        """
        # Evidence that a custom service for UDP/708 exists (optional but helpful)
        svc_has_708 = ("udp-portrange 708" in svc_lower) or ("set udp-portrange 708" in svc_lower)

        # Accept rule evidence
        accept_evidence = (
            ("config firewall local-in-policy" in local_in_lower)
            and ("set action accept" in local_in_lower)
            and (("set service \"fgsp\"" in local_in_lower) or ("set service fgsp" in local_in_lower) or svc_has_708)
            and (
                ("set srcaddr \"fgsp_peer_ips\"" in local_in_lower)
                or ("set srcaddr fgsp_peer_ips" in local_in_lower)
                or ("set srcaddrgrp \"fgsp_peer_ips\"" in local_in_lower)
                or ("set srcaddrgrp fgsp_peer_ips" in local_in_lower)
                or ("fgsp_peer" in local_in_lower)
            )
        )

        # Deny rule evidence
        deny_evidence = (
            ("set action deny" in local_in_lower)
            and (("set service \"fgsp\"" in local_in_lower) or ("set service fgsp" in local_in_lower) or svc_has_708)
            and (("set srcaddr \"all\"" in local_in_lower) or ("set srcaddr all" in local_in_lower))
        )

        # Addrgrp evidence (optional)
        addrgrp_evidence = ("config firewall addrgrp" in addrgrp_lower) and ("fgsp_peer" in addrgrp_lower)

        return accept_evidence and deny_evidence and (addrgrp_evidence or True)

    version_vuln, parsed_v, version_rationale = _is_version_vulnerable(version_text)
    fgsp_on = _fgsp_enabled(ha_text)

    # If FGSP isn't enabled, the described attack path (crafted FGSP session sync packets) is not applicable.
    if not fgsp_on:
        return

    restricted = _fgsp_port_708_restricted(local_in_text, svc_text, addrgrp_text)
    config_vuln = not restricted

    is_vulnerable = version_vuln and config_vuln

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-22251 (Fortinet FortiOS): "
        "an unauthenticated attacker may inject unauthorized sessions via crafted FGSP session synchronization packets "
        "(improper restriction of communication channel to intended endpoints, CWE-923). "
        f"Detected affected FortiOS version ({'.'.join(map(str, parsed_v)) if parsed_v else 'unparsed'}; {version_rationale}) "
        "and FGSP appears enabled, while UDP/708 (FGSP) does not appear restricted to intended peer IPs via local-in policy "
        "on the FGSP session synchronization interface. "
        "Remediation: upgrade to FortiOS 7.6.1+ (for 7.6.0) or 7.4.6+ (for 7.4.0-7.4.5), or migrate to a fixed release "
        "for 7.2/7.0/6.4 trains; and apply the workaround by restricting UDP/708 to FGSP peers using local-in policies. "
        "Advisory: https://www.fortiguard.com/psirt/FG-IR-24-287"
    )