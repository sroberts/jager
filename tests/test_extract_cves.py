import nose
from jager import *

def test_cve():
    assert(extract_cves('CVE-1976-0903') == ['CVE-1976-0903'])
