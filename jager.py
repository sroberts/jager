#!/usr/bin/env python
# encoding: utf-8
"""
jager.py

Created by Scott Roberts.
Copyright (c) 2013 TogaFoamParty Studios. All rights reserved.
"""

import argparse
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime

import bs4
import magic
import requests
from parsers.pdf import JagerPDF
from utilitybelt import utilitybelt as util

'''
# Setup Logging
import logging
logger = logging.getLogger('default')
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
# Setup logging to file
fh = logging.FileHandler('default.log')
fh.setLevel(logging.DEBUG)
logger.addHandler(fh)
# Setup logging to console
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
logger.addHandler(ch)
# Setup logging to syslog
import logging.handlers
sh = logging.handlers.SysLogHandler()
sh.setLevel(logging.DEBUG)
logger.addHandler(sh)

# 'application' code
logger.debug('debug message')
logger.info('info message')
logger.warn('warn message')
logger.error('error message')
logger.critical('critical message')
'''

# Setup File Magic
# m = magic.open(magic.MAGIC_MIME)
# m.load()

# Switches
VERBOSE = False

# Text Extractors:


def www_text_extractor(target):
    response = requests.get(target)
    soup = bs4.BeautifulSoup(response.text)
    [s.extract() for s in soup('script')]
    return soup.body.get_text()


# Meta Data

def file_metadata(path, tlp='green'):
    print "- Extracting: Source File Metadata"

    hash_sha1 = hashlib.sha1(open(path, 'rb').read()).hexdigest()
    filesize = os.path.getsize(path)
    filename = path.split('/')[-1]
    filetype = magic.from_file(path)

    print "- Metadata Generated"

    return {"sha1": hash_sha1, "filesize": filesize, "filename": filename, "filetype": filetype}


# Data Extractors
def extract_hashes(t):
    print "- Extracting: Hashes"

    md5s = list(set(re.findall(util.re_md5, t)))
    sha1s = list(set(re.findall(util.re_sha1, t)))
    sha256s = list(set(re.findall(util.re_sha256, t)))
    sha512s = list(set(re.findall(util.re_sha512, t)))
    ssdeeps = list(set(re.findall(util.re_ssdeep, t)))

    print " - %s MD5s detected." % len(md5s)
    print " - %s SHA1s detected." % len(sha1s)
    print " - %s SHA256s detected." % len(sha256s)
    print " - %s SHA512s detected." % len(sha512s)
    print " - %s ssdeeps detected." % len(ssdeeps)

    return {"md5s": md5s, "sha1s": sha1s, "sha256": sha256s, "sha512": sha512s, "ssdeep": ssdeeps}


def extract_emails(t):
    print "- Extracting: Email Addresses"

    emails = list(set(re.findall(util.re_email, t)))
    emails.sort()

    print " - %d email addresses detected." % (len(emails))

    return emails


def extract_ips(t):
    print "- Extracting: IPv4 Addresses"

    ips = re.findall(util.re_ipv4, t)
    ips = list(set(ips))
    for each in ips:
        if util.is_reserved(each):
            ips.remove(each)
    ips.sort()

    print " - %d IPv4 addresses detected." % len(ips)

    return {"ipv4addresses": ips, "ipv6addresses": []}


def extract_cves(t):
    print "- Extracting: CVE Identifiers"

    cves = re.findall(util.re_cve, t)
    cves = list(set(cves))

    cves = [cve[0] for cve in cves]

    print " - %d CVE identifiers detected." % len(cves)

    return cves


def extract_domains(t):
    print "- Extracting: Domains"

    domains = []

    t = t.split("\n")

    for line in t:
        hit = re.search(util.re_fqdn, line)
        if hit:
            domains.append(hit.group().lower())

    domains = list(set(domains))
    domains.sort()

    print " - %d domains detected." % len(domains)

    return domains


def extract_urls(t):
    print "- Extracting: URLs"
    urls = re.findall(util.re_url, t)
    # eliminate repeats
    urls = list(set(urls))
    filter(None, urls)
    urls.sort()

    print " - %d URLs detected." % len(urls)

    return urls


def extract_filenames(t):
    print "- Extracting: File Names"

    docs = list(set(["".join(doc) for doc in re.findall(util.re_doc, t)]))
    exes = list(set(["".join(item) for item in re.findall(util.re_exe, t)]))
    webs = list(set(["".join(item) for item in re.findall(util.re_web, t)]))
    zips = list(set(["".join(item) for item in re.findall(util.re_zip, t)]))
    imgs = list(set(["".join(item) for item in re.findall(util.re_img, t)]))
    flashes = list(set(["".join(item) for item in re.findall(util.re_flash, t)]))

    docs.sort()
    exes.sort()
    webs.sort()
    zips.sort()
    imgs.sort()
    flashes.sort()

    print " - %s Docs detected." % len(docs)
    print " - %s Executable files detected." % len(exes)
    print " - %s Web files detected." % len(webs)
    print " - %s Zip files detected." % len(zips)
    print " - %s Image files detected." % len(imgs)
    print " - %s Flash files detected." % len(flashes)

    return {"documents": docs, "executables": exes, "compressed": zips, "flash": flashes, "web": webs}


# Output Generators
def generate_json(text, metadata, tlp='red'):

    group_json = {
        "group_name": [
            "?"
        ],
        "attribution": [
            "?"
        ],
        "indicators": {
            "ips": extract_ips(text),
            "urls": extract_urls(text),
            "domains": extract_domains(text),
            "emails": extract_emails(text)
        },
        "malware": {
            "filenames": extract_filenames(text),
            "hashes": extract_hashes(text)
        },
        "cves": extract_cves(text),
        "metadata": {
            "report_name": "??",
            "date_analyzed": time.strftime("%Y-%m-%d %H:%M"),
            "source": "??",
            "release_date": "??",
            "tlp": tlp,
            "authors": [
                "??"
            ],
            "file_metadata": metadata
        }
    }

    return group_json


def get_time():
    now = datetime.isoformat(datetime.now())
    now = now.replace(':', '_').split('.')[0]
    return now


def title():
    ascii_art = """
   __
   \ \  __ _  __ _  ___ _ __
    \ \/ _` |/ _` |/ _ \ '__|
 /\_/ / (_| | (_| |  __/ |
 \___/ \__,_|\__, |\___|_|    IOC Extractor
             |___/

"""
    print ascii_art


# Interface
def main():
    '''Where the initial work happens...'''
    title()

    parser = argparse.ArgumentParser(prog=sys.argv[0])

    parser.add_argument("-p", "--pdf", help="Specify an input.", action="store",
                        default=None, type=str, dest="in_pdf", required=False)

    parser.add_argument("-o", "--output", help="Specify an output.", action="store",
                        default="output.json", type=str, dest="out_path", required=False)

    parser.add_argument("-d", "--directory", help="WIP: Specify a directory to analyze.",
                        action="store", default=None, type=str, dest="in_directory", required=False)

    parser.add_argument("-u", "--url", help="WIP: Analyze webpage.", action="store",
                        default=None, type=str, dest="in_url", required=False)

    parser.add_argument("-t", "--text", help="NOT IMPLIMENTED: Analyze text file.",
                        action="store", default=None, type=str, dest="in_text", required=False)

    parser.add_argument("-v", "--verbose", help="Prints lots of status messages.",
                        action="store_true", dest="verbose", default=True, required=False)

    args = parser.parse_args()

    if args.in_pdf and args.out_path:
        # Input of a PDF out to JSON
        if os.path.exists(os.path.abspath(args.out_path)):
            print 'error: output file %s all ready exists!' % args.out_path
            out_path = '%s_%s.json' % (os.path.splitext(args.out_path)[0], get_time())
            print 'using output file %s' % out_path
        else:
            out_path = args.out_path

        out_file = open(os.path.abspath(out_path), 'w')

        if not os.path.exists(os.path.abspath(args.in_pdf)):
            print 'error: input PDF %s does not exist!' % args.in_pdf
            out_file.close()
            os.remove(os.path.abspath(out_path))
            sys.exit(1)
        in_file = os.path.abspath(args.in_pdf)

        metadata = file_metadata(in_file)

        pdftext = str(JagerPDF(in_file))
        outjson = json.dumps(generate_json(pdftext, metadata), indent=4)

        out_file.write(outjson)
        out_file.close()

    elif args.in_url and args.out_path:
        # Input of a website out to JSON
        print "WIP: You are trying to analyze: %s and output to %s" % (args.in_url, args.out_path)

        # Should we be verifying this is a valid URL?
        r = requests.get(args.in_url)
        return r
        # You aren"t writing the JSON response here to anything, right?
        # It just returns the requests object.
        # should it be something like:
        # r = requests.get(options.in_url)
        # if r.status_code == 200:
        #     json_out = r.json()
        #     ....
        #     out_file.write(json_out)
        #     out_file.close()

    elif args.in_directory and args.out_path:
        # Input directory, expand directory and output to json
        print "WIP: You are trying to analyze all the PDFs in %s and output to %s" % (args.in_directory, args.out_path)

        # An invalid dir or non-existent dir will crash the app
        if os.path.exists(args.in_directory):
            if not os.path.isdir(args.in_directory):
                print "error: input %s is not a valid directory" % args.in_directory
                sys.exit(1)
        else:
            print "error: input directory %s does not exist" % args.in_directory
            sys.exit(1)

        if not os.path.exists(args.out_path) or not os.path.isdir(args.out_path):
            print "error: output directory %s is not usable" % args.out_path
            sys.exit(1)

        for root, dirs, files in os.walk(os.path.abspath(args.in_directory)):
            # `file` in Python denotes a file like object.
            # change this to f" to avoid confusion?
            for f in files:
                if f.endswith(".pdf"):
                    try:
                        print "- Analyzing File: %s" % (f)
                        out_filename = "%s/%s.json" % (args.out_path, f.split('/')[-1].split(".")[0])
                        out_file = open(out_filename, 'w')

                        out_file.write(json.dumps(generate_json(
                            str(JagerPDF(os.path.join(root, f))),
                            file_metadata(os.path.join(root, f)),
                            'green'), indent=4))
                        out_file.close()

                    except IOError as e:
                        current_ts = time.strftime("%Y-%m-%d %H:%M")
                        with open("error.txt", "a+") as error:
                            error.write("%s - IOError on %s: %s\n" % (current_ts, os.path.join(root, f), e))

    elif args.in_text and args.out_path:
        # Input of a textfile and output to json
        print "NOT IMPLEMENTED: You are trying to analyze %s and output to %s" % (args.in_text, args.out_path)

    else:
        print "That set of options won't get you what you need.\n"
        parser.print_help()

    return True

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print "User aborted."
    except SystemExit:
        pass
