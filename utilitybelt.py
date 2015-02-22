#!/usr/bin/env python
# encoding: utf-8
"""
 _   _ _   _ _ _ _          ______      _ _
| | | | | (_) (_) |         | ___ \    | | |
| | | | |_ _| |_| |_ _   _  | |_/ / ___| | |_
| | | | __| | | | __| | | | | ___ \/ _ \ | __|
| |_| | |_| | | | |_| |_| | | |_/ /  __/ | |_
 \___/ \__|_|_|_|\__|\__, | \____/ \___|_|\__|
                      __/ |
                     |___/

A library to make you a Python CND Batman
"""

import re
import socket
import struct

import GeoIP
import requests
from netaddr import IPNetwork

gi = GeoIP.open("./data/GeoLiteCity.dat", GeoIP.GEOIP_STANDARD)

# Indicators
re_ipv4 = re.compile("(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)", re.I | re.S | re.M)
re_email = re.compile("\\b[A-Za-z0-9_.]+@[0-9a-z.-]+\\b", re.I | re.S | re.M)
re_fqdn = re.compile('(?=^.{4,255}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)', re.I | re.S | re.M)
re_domain = re.compile("([a-z0-9-_]+\\.){1,4}(com|aero|am|asia|au|az|biz|br|ca|\
cat|cc|ch|co|coop|cx|de|edu|fr|gov|hk|info|int|ir|jobs|jp|kr|kz|me|mil|mobi|museum\
|name|net|nl|nr|org|post|pre|ru|tel|tk|travel|tw|ua|uk|uz|ws|xxx)", re.I | re.S | re.M)
re_cve = re.compile("(CVE-(19|20)\\d{2}-\\d{4,7})", re.I | re.S | re.M)
re_url = re.compile(ur'(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)\
(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)\
|[^\s`!()\[\]{};:\'".,<>?\xab\xbb\u201c\u201d\u2018\u2019]))')

# Hashes
re_md5 = re.compile("\\b[a-f0-9]{32}\\b", re.I | re.S | re.M)
re_sha1 = re.compile("\\b[a-f0-9]{40}\\b", re.I | re.S | re.M)
re_sha256 = re.compile("\\b[a-f0-9]{64}\\b", re.I | re.S | re.M)
re_sha512 = re.compile("\\b[a-f0-9]{128}\\b", re.I | re.S | re.M)
re_ssdeep = re.compile("\\b\\d{2}:[A-Za-z0-9/+]{3,}:[A-Za-z0-9/+]{3,}\\b", re.I | re.S | re.M)

# File Types
re_doc = '\W([\w-]+\.)(docx|doc|csv|pdf|xlsx|xls|rtf|txt|pptx|ppt)'
re_web = '\W([\w-]+\.)(html|htm|php|js)'
re_exe = '\W([\w-]+\.)(exe|dll|jar)'
re_zip = '\W([\w-]+\.)(zip|zipx|7z|rar|tar|gz)'
re_img = '\W([\w-]+\.)(jpeg|jpg|gif|png|tiff|bmp)'
re_flash = '\W([\w-]+\.)(flv|swf)'

# TODO: submit this upstream
whitelist = [{'net': IPNetwork('10.0.0.0/8'), 'org': 'Private per RFC 1918'},
             {'net': IPNetwork('172.16.0.0/12'), 'org': 'Private per RFC 1918'},
             {'net': IPNetwork('192.168.0.0/16'), 'org': 'Private per RFC 1918'},
             {'net': IPNetwork('0.0.0.0/8'), 'org': 'Invalid per RFC 1122'},
             {'net': IPNetwork('127.0.0.0/8'), 'org': 'Loopback per RFC 1122'},
             {'net': IPNetwork('169.254.0.0/16'), 'org': 'Link-local per RFC 3927'},
             {'net': IPNetwork('100.64.0.0/10'), 'org': 'Shared address space per RFC 6598'},
             {'net': IPNetwork('192.0.0.0/24'), 'org': 'IETF Protocol Assignments per RFC 6890'},
             {'net': IPNetwork('192.0.2.0/24'), 'org': 'Documentation and examples per RFC 6890'},
             {'net': IPNetwork('192.88.99.0/24'), 'org': 'IPv6 to IPv4 relay per RFC 3068'},
             {'net': IPNetwork('198.18.0.0/15'), 'org': 'Network benchmark tests per RFC 2544'},
             {'net': IPNetwork('198.51.100.0/24'), 'org': 'Documentation and examples per RFC 5737'},
             {'net': IPNetwork('203.0.113.0/24'), 'org': 'Documentation and examples per RFC 5737'},
             {'net': IPNetwork('224.0.0.0/4'), 'org': 'IP multicast per RFC 5771'},
             {'net': IPNetwork('240.0.0.0/4'), 'org': 'Reserved per RFC 1700'},
             {'net': IPNetwork('255.255.255.255/32'), 'org': 'Broadcast address per RFC 919'}]

useragent = 'Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0'


def ip_to_long(ip):
    """Convert an IPv4Address string to long"""
    packedIP = socket.inet_aton(ip)
    return struct.unpack("!L", packedIP)[0]


def ip_between(ip, start, finish):
    """Checks to see if IP is between start and finish"""

    if is_ipv4(ip) and is_ipv4(start) and is_ipv4(finish):
        ip_long = ip_to_long(ip)
        start_long = ip_to_long(start)
        finish_long = ip_to_long(finish)

        if start_long <= ip_long <= finish_long:
            return True
        else:
            return False
    else:
        return False


def is_rfc1918(ip):
    if ip_between(ip, "10.0.0.0", "10.255.255.255"):
        return True
    elif ip_between(ip, "172.16.0.0", "172.31.255.255"):
        return True
    elif ip_between(ip, "192.168.0.0", "192.168.255.255"):
        return True
    else:
        return False


def is_reserved(ip):
    if ip_between(ip, "0.0.0.0", "0.255.255.255"):
        return True
    elif ip_between(ip, "10.0.0.0", "10.255.255.255"):
        return True
    elif ip_between(ip, "100.64.0.0", "100.127.255.255"):
        return True
    elif ip_between(ip, "127.0.0.0", "127.255.255.255"):
        return True
    elif ip_between(ip, "169.254.0.0", "169.254.255.255"):
        return True
    elif ip_between(ip, "172.16.0.0", "172.31.255.255"):
        return True
    elif ip_between(ip, "192.0.0.0", "192.0.0.255"):
        return True
    elif ip_between(ip, "192.0.2.0", "192.0.2.255"):
        return True
    elif ip_between(ip, "192.88.99.0", "192.88.99.255"):
        return True
    elif ip_between(ip, "192.168.0.0", "192.168.255.255"):
        return True
    elif ip_between(ip, "198.18.0.0", "198.19.255.255"):
        return True
    elif ip_between(ip, "198.51.100.0", "198.51.100.255"):
        return True
    elif ip_between(ip, "203.0.113.0", "203.0.113.255"):
        return True
    elif ip_between(ip, "224.0.0.0", "255.255.255.255"):
        return True
    else:
        return False


def is_ipv4(ipv4address):
    """Returns true for valid IPv4 Addresses, false for invalid."""

    return bool(re.match(re_ipv4, ipv4address))


def is_fqdn(address):
    """Returns true for valid DNS addresses, false for invalid."""

    return re.match(re_fqdn, address)


def ip_to_geo(ipaddress):
    """Convert IP to Geographic Information"""

    return gi.record_by_addr(ipaddress)


def domain_to_geo(domain):
    """Convert Domain to Geographic Information"""

    return gi.record_by_name(domain)


def ip_to_geojson(ipaddress, name="Point"):
    """Generate GeoJSON for given IP address"""

    geo = ip_to_geo(ipaddress)

    point = {
        "type": "FeatureCollection",
        "features": [
            {
                "type": "Feature",
                "properties": {
                    "name": name
                },
                "geometry": {
                    "type": "Point",
                    "coordinates": [
                        geo["longitude"],
                        geo["latitude"]
                    ]
                }
            }
        ]
    }

    return point


def ips_to_geojson(ipaddresses):
    """Generate GeoJSON for given IP address"""

    features = []

    for ipaddress in ipaddresses:
        geo = gi.record_by_addr(ipaddress)

        features.append({
            "type": "Feature",
            "properties": {
                "name": ipaddress
            },
            "geometry": {
                "type": "Point",
                "coordinates": [
                    geo["longitude"],
                    geo["latitude"]
                ]
            }
        })

    points = {
        "type": "FeatureCollection",
        "features": features
    }

    return points


def reverse_dns_sna(ipaddress):
    """Returns a list of the dns names that point to a given ipaddress using StatDNS API"""

    r = requests.get("http://api.statdns.com/x/%s" % ipaddress)

    if r.status_code == 200:
        names = []

        for item in r.json()['answer']:
            name = str(item['rdata']).strip(".")
            names.append(name)

        return names
    else:
        raise Exception("No PTR record for %s" % ipaddress)
        return ""


def reverse_dns(ipaddress):
    """Returns a list of the dns names that point to a given ipaddress"""

    name, alias, addresslist = socket.gethostbyaddr(ipaddress)
    return [str(name)]


def vt_ip_check(ip, vt_api):
    """Checks VirusTotal for occurrences of an IP address"""
    if not is_ipv4(ip):
        return None

    try:
        url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        parameters = {'ip': ip, 'apikey': vt_api}
        response = requests.get(url, params=parameters)
        return response.json()
    except:
        return None


def vt_name_check(domain, vt_api):
    """Checks VirusTotal for occurrences of a domain name"""
    if not is_fqdn(domain):
        return None

    try:
        url = 'https://www.virustotal.com/vtapi/v2/domain/report'
        parameters = {'domain': domain, 'apikey': vt_api}
        response = requests.get(url, params=parameters)
        return response.json()
    except:
        return None


def he_ip_check(ip):
    """Checks Hurricane Electric for DNS information on an IP address"""
    if not is_ipv4(ip):
        return None

    url = 'http://bgp.he.net/ip/%s#_dns' % ip
    headers = {'User-Agent': useragent}
    response = requests.get(url, headers=headers)
    if response.text:
        # TODO: use BeautifulSoup
        pattern = re.compile('\/dns\/.+\".title\=\".+\"\>(.+)<\/a\>', re.IGNORECASE)
        hostnames = re.findall(pattern, response.text)
        return hostnames
    else:
        return None


def he_name_check(domain):
    """Checks Hurricane Electric for DNS information on an IP address"""
    if not is_fqdn(domain):
        return None

    url = 'http://bgp.he.net/dns/%s#_whois' % domain
    headers = {'User-Agent': useragent}
    response = requests.get(url, headers=headers)
    if response.text:
        # TODO: use BeautifulSoup
        pattern = re.compile('\/dns\/.+\".title\=\".+\"\>(.+)<\/a\>', re.IGNORECASE)
        hostnames = re.findall(pattern, response.text)
        return hostnames
    else:
        return None


def isc_ip_check(ip):
    """Checks SANS ISC for attack data on an IP address"""
    if not is_ipv4(ip):
        return None

    try:
        url = 'https://isc.sans.edu/api/ip/%s?json' % ip
        headers = {'User-Agent': useragent}
        response = requests.get(url, headers=headers)
        data = response.json()
        return {'count': data['count']['text'],
                'attacks': data['attacks']['text'],
                'mindate': data['mindate']['text'],
                'maxdate': data['maxdate']['text']}
    except:
        return None


def pdns_ip_check(ip, dnsdb_api):
    """Checks Farsight passive DNS for information on an IP address"""
    if not is_ipv4(ip):
        return None

    url = 'https://api.dnsdb.info/lookup/rdata/ip/%s?limit=50' % ip
    headers = {'Accept': 'application/json', 'X-Api-Key': dnsdb_api}

    response = requests.get(url, headers=headers)
    return response.json()


def pdns_name_check(name, dnsdb_api):
    """Checks Farsight passive DNS for information on a name"""
    if not is_fqdn(name):
        return None

    url = 'https://api.dnsdb.info/lookup/rrset/name/%s?limit=50' % name
    headers = {'Accept': 'application/json', 'X-Api-Key': dnsdb_api}

    response = requests.get(url, headers=headers)
    return response.json()


def ipinfo_ip_check(ip):
    """Checks ipinfo.io for basic WHOIS-type data on an IP address"""
    if not is_ipv4(ip):
        return None

    response = requests.get('http://ipinfo.io/%s/json' % ip)
    return response.json()
