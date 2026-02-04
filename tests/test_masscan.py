"""Tests for masscan parsing."""

from clawpwn.tools.masscan import MasscanScanner


def test_masscan_parse_multiple_hosts():
    output = """[
      {"ip":"192.168.1.10","ports":[{"port":80,"proto":"tcp","status":"open"}]},
      {"ip":"192.168.1.10","ports":[{"port":443,"proto":"tcp","status":"open"}]},
      {"ip":"192.168.1.20","ports":[{"port":22,"proto":"tcp","status":"open"}]}
    ]"""

    results = MasscanScanner._parse_masscan_json(output)
    assert len(results) == 2

    host10 = next(r for r in results if r.ip == "192.168.1.10")
    ports10 = sorted(p.port for p in host10.ports)
    assert ports10 == [80, 443]

    host20 = next(r for r in results if r.ip == "192.168.1.20")
    assert [p.port for p in host20.ports] == [22]


def test_masscan_parse_empty():
    assert MasscanScanner._parse_masscan_json("") == []
