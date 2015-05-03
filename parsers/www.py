#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
www.py

Created by Scott Roberts.
Copyright (c) 2013 TogaFoamParty Studios. All rights reserved.

A module for Jager to extract plain text from websites.
"""

import sys

import requests
from bs4 import BeautifulSoup

headers = {
    'User-Agent': 'curl/7.21.4 (universal-apple-darwin11.0) libcurl/7.21.4 OpenSSL/0.9.8r zlib/1.2.5',
}


class JagerWWW:

    # regex = "" # WIP: Check to ensure submitted value is a http link
    text = ""

    def __init__(self, website):
        self.text = self.extractor(website)

    def extractor(self, website):
        html = requests.get(website, headers=headers, verify=False)
        soup = BeautifulSoup(html.text, "html.parser")

        return soup.get_text()

    def __str__(self):

        try:
            return str(self.text)
        except UnicodeEncodeError:
            print "Unicode is a pain..."
            return self.text.encode('utf-8').strip()
            # raise


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
