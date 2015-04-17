"""
 _   _ _   _ _ _ _          ______      _ _
| | | | | (_) (_) |         | ___ \    | | |
| | | | |_ _| |_| |_ _   _  | |_/ / ___| | |_
| | | | __| | | | __| | | | | ___ \/ _ \ | __|
| |_| | |_| | | | |_| |_| | | |_/ /  __/ | |_
 \___/ \__|_|_|_|\__|\__, | \____/ \___|_|\__|
                      __/ |
                     |___/

A library to make you a Python CND Ba   tman
"""

import GeoIP
import requests
import json
import re
import socket
import struct

gi = GeoIP.open("data/GeoLiteCity.dat", GeoIP.GEOIP_STANDARD)

# Indicators
re_ipv4 = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", re.I | re.S | re.M)
re_email = re.compile("\\b[A-Za-z0-9_.]+@[0-9a-z.-]+\\b", re.I | re.S | re.M)
re_domain = re.compile("([a-z0-9-_]+\\.){1,4}(com|aero|am|asia|au|az|biz|br|ca|cat|cc|ch|co|coop|cx|de|edu|fr|gov|hk|info|int|ir|jobs|jp|kr|kz|me|mil|mobi|museum|name|net|nl|nr|org|post|pre|ru|tel|tk|travel|tw|ua|uk|uz|ws|xxx)", re.I | re.S | re.M)
re_cve = re.compile("(CVE-(19|20)\\d{2}-\\d{4,7})", re.I | re.S | re.M)

# Hashes
re_md5 = re.compile("\\b[a-f0-9]{32}\\b", re.I | re.S | re.M)
re_sha1 = re.compile("\\b[a-f0-9]{40}\\b", re.I | re.S | re.M)
re_sha256 = re.compile("\\b[a-f0-9]{64}\\b", re.I | re.S | re.M)
re_sha512 = re.compile("\\b[a-f0-9]{128}\\b", re.I | re.S | re.M)
re_ssdeep = re.compile("\\b\\d{2}:[A-Za-z0-9/+]{3,}:[A-Za-z0-9/+]{3,}\\b", re.I | re.S | re.M)

# File Types
re_doc = '\W([\w-]+\.)(docx|doc|csv|pdf|xlsx|xls|rtf|txt|pptx|ppt)'
re_web = '\W([\w-]+\.)(html|php|js)'
re_exe = '\W([\w-]+\.)(exe|dll|jar)'
re_zip = '\W([\w-]+\.)(zip|zipx|7z|rar|tar|gz)'
re_img = '\W([\w-]+\.)(jpeg|jpg|gif|png|tiff|bmp)'
re_flash = '\W([\w-]+\.)(flv|swf)'


gi = GeoIP.open("./data/GeoLiteCity.dat", GeoIP.GEOIP_STANDARD)


def ip_to_long(ip):
    """Convert an IPv4Address string to long"""
    packedIP = socket.inet_aton(ip)
    return struct.unpack("!L", packedIP)[0]


def ip_between(ip, start, finish):
    """Checks to see if IP is between start and finish"""

    if is_IPv4Address(ip) and is_IPv4Address(start) and is_IPv4Address(finish):
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


def is_IPv4Address(ipv4address):
    """Returns true for valid IPv4 Addresses, false for invalid."""

    return bool(re.match(re_ipv4, ipv4address))


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
