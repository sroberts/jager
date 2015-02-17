# import nose
from jager import extract_ips


def test_extract_ips():
    good_ips = ['192.168.1.1',
                '192.168.001.001',
                '1.1.1.1',
                '254.254.254.254']
    bad_ips = ['1.1.1',
               '1256.1256.1256.1256']
    for ip in good_ips:
        assert(extract_ips(ip)['ipv4addresses'][0] == ip)
    for ip in bad_ips:
        assert(extract_ips(ip)['ipv4addresses'] == [])
