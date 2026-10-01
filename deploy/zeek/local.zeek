# Agentic SOC Zeek site policy: /opt/zeek/share/zeek/site/local.zeek
# Zeek provides network context (conn, dns, http, ssl, files); Suricata provides signatures.
# After editing: /opt/zeek/bin/zeekctl check && /opt/zeek/bin/zeekctl deploy

# Machine-readable logs for the Wazuh JSON decoder.
@load policy/tuning/json-logs.zeek

@load tuning/defaults
@load misc/loaded-scripts
@load misc/capture-loss
@load misc/stats

# Context the orchestrator and analysts use.
@load protocols/conn/known-hosts
@load protocols/conn/known-services
@load protocols/ssl/known-certs
@load protocols/ssl/validate-certs        # validation_status in ssl.log (rule 100103)
@load protocols/dns/detect-external-names
@load protocols/ssh/detect-bruteforcing
@load protocols/http/detect-sqli
@load frameworks/software/vulnerable
@load frameworks/files/hash-all-files     # md5/sha1/sha256 in files.log for threat-intel lookups

# Scan detection notices (Scan::Port_Scan / Scan::Address_Scan, rule 100102). Recent Zeek
# releases may no longer ship this script; if `zeekctl check` reports it missing, remove the
# line and install a scan-detection package with zkg instead.
@load misc/scan

# Community ID lets analysts pivot between Zeek conn.log and Suricata EVE records.
@load policy/protocols/conn/community-id-logging

# Deliberately not loaded: frameworks/files/detect-MHR (sends file hashes to an external DNS
# service) and geo-data scripts (need a GeoIP database; the lab is isolated).
