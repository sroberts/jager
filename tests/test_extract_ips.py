# import nose
from jager import extract_ips


def test_extract_ips():
    good_ips = ['8.8.8.8',
                '1.1.1.1',
                '129.110.10.1']
    bad_ips = ['192.168.1.1',
               '254.254.254.254',
               '1.1.1',
               '1256.1256.1256.1256']
    for ip in good_ips:
        print "Testing %s" % ip
        assert(extract_ips(ip)['ipv4addresses'][0] == ip)
    for ip in bad_ips:
        print "Testing %s" % ip
        assert(extract_ips(ip)['ipv4addresses'] == [])
