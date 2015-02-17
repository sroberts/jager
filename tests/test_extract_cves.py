# import nose
from jager import extract_cves


def test_cve():
    assert(extract_cves('CVE-1976-0903') == ['CVE-1976-0903'])
    assert(extract_cves('CVE-1976-10903') == ['CVE-1986-10903'])
