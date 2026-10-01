from agentic_soc.integrations.wazuh import (
    NetworkClassifier,
    alert_fingerprint,
    normalize_user,
    normalize_wazuh_alert,
    parse_hashes,
)
from agentic_soc.models.schemas import EntityType
from evaluation import scenarios as sc

CLASSIFIER = NetworkClassifier(["192.168.50.0/24"])


def test_sysmon_alert_normalization():
    raw = sc.phishing_powershell(0).alerts[4]  # PowerShell writes upd.exe
    alert = normalize_wazuh_alert(raw, CLASSIFIER)
    assert alert.source == "sysmon"
    assert alert.agent_name == "win-client01"
    assert alert.user == "alice"  # domain prefix stripped
    assert alert.hashes["sha256"] == sc.DROPPER_SHA256
    assert alert.timestamp.tzinfo is not None
    kinds = {(e.type, e.value) for e in alert.entities}
    assert (EntityType.HOST, "win-client01") in kinds
    assert (EntityType.HASH, sc.DROPPER_SHA256) in kinds
    assert (EntityType.IP, "192.168.50.60") in kinds  # host's own address, for network correlation


def test_suricata_alert_does_not_treat_sensor_as_victim():
    raw = sc.scan_exploit(0).alerts[2]
    alert = normalize_wazuh_alert(raw, CLASSIFIER)
    assert alert.source == "suricata"
    assert alert.src_ip == sc.KALI and alert.dst_ip == "192.168.50.70"
    assert alert.signature.startswith("ET WEB_SERVER")
    assert not any(e.type == EntityType.HOST for e in alert.entities)
    src = next(e for e in alert.entities if e.value == sc.KALI)
    assert src.attributes == {"internal": True, "role": "source"}


def test_zeek_literal_dotted_keys():
    raw = sc.scan_exploit(0).alerts[0]
    alert = normalize_wazuh_alert(raw, CLASSIFIER)
    assert alert.source == "zeek"
    assert alert.src_ip == sc.KALI
    assert alert.dst_ip == "192.168.50.70"


def test_external_ip_classification():
    raw = sc.phishing_powershell(0).alerts[3]
    alert = normalize_wazuh_alert(raw, CLASSIFIER)
    c2 = next(e for e in alert.entities if e.value == sc.C2_IP)
    assert c2.attributes["internal"] is False


def test_fingerprint_ignores_timestamp():
    a, b = sc.credential_lateral(0).alerts[:2]
    assert a["timestamp"] != b["timestamp"]
    assert alert_fingerprint(normalize_wazuh_alert(a)) == alert_fingerprint(normalize_wazuh_alert(b))


def test_helpers():
    assert normalize_user("NT AUTHORITY\\SYSTEM") is None
    assert normalize_user("WIN-CLIENT01$") is None
    assert normalize_user("bob@lab.local") == "bob"
    assert parse_hashes("SHA1=" + "a" * 40 + ",MD5=" + "b" * 32 + ",IMPHASH=zz") == {"sha1": "a" * 40, "md5": "b" * 32}
    assert parse_hashes("not-a-hash") == {}
