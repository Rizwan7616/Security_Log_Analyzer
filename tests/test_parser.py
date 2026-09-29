from src.parser import analyze_auth_log

def test_brute_force_detection(tmp_path):
    # Create an automated mock log file
    test_log = tmp_path / "test_auth.log"
    content = (
        "Failed password for root from 10.0.0.5 port 22 ssh2\n"
        "Failed password for root from 10.0.0.5 port 23 ssh2\n"
        "Failed password for admin from 10.0.0.5 port 24 ssh2\n"
        "Accepted password for dev from 10.0.0.9 port 25 ssh2\n"
    )
    test_log.write_text(content, encoding="utf-8")

    result = analyze_auth_log(str(test_log), threshold=3)
    assert result["total_failures"] == 3
    assert "10.0.0.5" in result["threats_detected"]
    assert "sudo ufw deny from 10.0.0.5" in result["mitigation_firewall_rules"]