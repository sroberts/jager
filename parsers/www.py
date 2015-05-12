#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
www.py

Created by Scott Roberts.
Copyright (c) 2013 TogaFoamParty Studios. All rights reserved.

A module for Jager to extract plain text from websites.
"""

import hashlib
import sys

import requests
from bs4 import BeautifulSoup

headers = {
    'User-Agent': 'curl/7.21.4 (universal-apple-darwin11.0) libcurl/7.21.4 OpenSSL/0.9.8r zlib/1.2.5',
}


class JagerWWW:

    text = ""

    useragent = ""

    def __init__(self, website):

        self.path = website
        self.text = self.extractor(website).encode('utf-8').strip()

    def extractor(self, website):
        html = requests.get(website, headers=headers, verify=False)
        soup = BeautifulSoup(html.text, "html.parser")

        return soup.get_text()

    def metadata(self):
        print "- Extracting: Webpage Metadata"

        hash_sha1 = hashlib.sha1(self.text).hexdigest()
        length = len(self.text)

        print "- Metadata Generated"

        return {"sha1": hash_sha1, "length": length}

    def __str__(self):

        return str(self.text)


def main():
    print "WWW Text Extraction: {}".format(sys.argv[1])
    p = JagerWWW(sys.argv[1])

    print str(p)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print "User aborted."
    except SystemExit:
        pass
