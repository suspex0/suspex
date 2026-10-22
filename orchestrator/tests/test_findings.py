from pathlib import Path

from suspex.findings import FindingsLedger


def test_record_update_evidence(tmp_path: Path) -> None:
    led = FindingsLedger(tmp_path / "f.db")
    sid = led.start_session("192.168.56.10:50074", notes="test session")
    fid = led.record(sid, "high", "Driver IOCTL lacks length validation",
                     "SUSPEX_IOCTL_USER_MEM_WRITE trusts caller size", refs="driver/src/Dispatcher.c")
    led.update(fid, status="confirmed")
    eid = led.add_evidence(fid, "hexdump", "41414141 41414141")
    assert eid

    findings = led.list_findings(sid)
    assert len(findings) == 1
    assert findings[0].status == "confirmed"
    assert findings[0].severity == "high"
    ev = led.evidence_for(fid)
    assert len(ev) == 1
    assert ev[0].kind == "hexdump"
    led.close()


def test_report_generation(tmp_path: Path) -> None:
    led = FindingsLedger(tmp_path / "f.db")
    sid = led.start_session("target-a")
    fid = led.record(sid, "critical", "Auth bypass in agent token check", "empty token accepted")
    led.add_evidence(fid, "command", "grpcurl -plaintext ... Status")
    out = led.generate_report(tmp_path / "reports", sid, title="Unit Test Report")
    md = Path(out["markdown"]).read_text(encoding="utf-8")
    html = Path(out["html"]).read_text(encoding="utf-8")
    assert "Auth bypass in agent token check" in md
    assert "[CRITICAL]" in md
    assert "Auth bypass" in html
    assert "Unit Test Report" in html
    led.close()


def test_export_json(tmp_path: Path) -> None:
    import json

    led = FindingsLedger(tmp_path / "f.db")
    sid = led.start_session("t")
    led.record(sid, "low", "t1", "d1")
    data = json.loads(led.export_json())
    assert len(data) == 1
    assert data[0]["evidence"] == []
    led.close()
