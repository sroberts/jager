#!/usr/bin/env python
# encoding: utf-8
"""
jager.py

Created by Scott Roberts.
Copyright (c) 2013 TogaFoamParty Studios. All rights reserved.
"""

import argparse
import glob
import hashlib
import json
import logging
import os
import re
import sys
import tempfile
import time
from datetime import datetime
from multiprocessing import Pool
from multiprocessing import cpu_count
from urlparse import urlparse

import bs4
import magic
import requests
from parsers.pdf import JagerPDF
from utilitybelt import utilitybelt as util

# Global settings, set from command line args
CONFIG_OUT_PATH = None
CONFIG_OUT_FILE = None
CONFIG_TLP = 'GREEN'
# logger = None
logger = getLogger()


def getLogger(verbose=False, filename=None):
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger = logging.getLogger('jager')
    # set logging level
    if verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO
    logger.setLevel(level)
    if filename:
        # Setup logging to file
        fh = logging.FileHandler(filename)
        fh.setLevel(level)
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    # Setup logging to console
    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    return logger

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
    logger.debug("+ Extracting: Source File Metadata")

    hash_sha1 = hashlib.sha1(open(path, 'rb').read()).hexdigest()
    filesize = os.path.getsize(path)
    filename = path.split('/')[-1]
    filetype = magic.from_file(path)

    logger.debug("- Metadata Generated")

    return {"sha1": hash_sha1, "filesize": filesize, "filename": filename, "filetype": filetype}


# Data Extractors
def extract_hashes(t):
    logger.debug("+ Extracting: Hashes")

    md5s = list(set(re.findall(util.re_md5, t)))
    sha1s = list(set(re.findall(util.re_sha1, t)))
    sha256s = list(set(re.findall(util.re_sha256, t)))
    sha512s = list(set(re.findall(util.re_sha512, t)))
    ssdeeps = list(set(re.findall(util.re_ssdeep, t)))

    logger.debug(" - %s MD5s detected." % len(md5s))
    logger.debug(" - %s SHA1s detected." % len(sha1s))
    logger.debug(" - %s SHA256s detected." % len(sha256s))
    logger.debug(" - %s SHA512s detected." % len(sha512s))
    logger.debug(" - %s ssdeeps detected." % len(ssdeeps))

    return {"md5s": md5s, "sha1s": sha1s, "sha256": sha256s, "sha512": sha512s, "ssdeep": ssdeeps}


def extract_emails(t):
    logger.debug("+ Extracting: Email Addresses")

    emails = list(set(re.findall(util.re_email, t)))
    emails.sort()

    logger.debug(" - %d email addresses detected." % (len(emails)))

    return emails


def extract_ips(t):
    global logger
    logger.debug("+ Extracting: IPv4 Addresses")

    ips = re.findall(util.re_ipv4, t)
    ips = list(set(ips))
    for each in ips:
        if util.is_reserved(each):
            ips.remove(each)
    ips.sort()

    logger.debug(" - %d IPv4 addresses detected." % len(ips))

    return {"ipv4addresses": ips, "ipv6addresses": []}


def extract_cves(t):
    global logger
    logger.debug("+ Extracting: CVE Identifiers")

    cves = re.findall(util.re_cve, t)
    cves = list(set(cves))

    cves = [cve[0] for cve in cves]

    logger.debug(" - %d CVE identifiers detected." % len(cves))

    return cves


def extract_domains(t):

    global logger
    logger.debug("+ Extracting: Domains")

    domains = []

    t = t.split("\n")

    for line in t:
        hit = re.search(util.re_fqdn, line)
        if re.search(util.re_fqdn, line):
            domains.append(hit.group().lower())

    domains = list(set(domains))
    domains.sort()

    logger.debug(" - %d domains detected." % len(domains))

    return domains


def extract_urls(t):

    global logger
    logger.debug("+ Extracting: URLs")
    urls = re.findall(util.re_url, t)
    # eliminate repeats
    urls = list(set(urls))
    filter(None, urls)
    urls.sort()

    logger.debug(" - %d URLs detected." % len(urls))

    return urls


def extract_filenames(t):

    global logger
    logger.debug("+ Extracting: File Names")

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

    logger.debug(" - %s Docs detected." % len(docs))
    logger.debug(" - %s Executable files detected." % len(exes))
    logger.debug(" - %s Web files detected." % len(webs))
    logger.debug(" - %s Zip files detected." % len(zips))
    logger.debug(" - %s Image files detected." % len(imgs))
    logger.debug(" - %s Flash files detected." % len(flashes))

    return {"documents": docs, "executables": exes, "compressed": zips, "flash": flashes, "web": webs}


# Output Generators
def generate_json(text, metadata, tlp='red'):

    group_json = {
        'group_name': [
            '?'
        ],
        'attribution': [
            '?'
        ],
        'indicators': {
            'ips': extract_ips(text),
            'urls': extract_urls(text),
            'domains': extract_domains(text),
            'emails': extract_emails(text)
        },
        'malware': {
            'filenames': extract_filenames(text),
            'hashes': extract_hashes(text)
        },
        'cves': extract_cves(text),
        'metadata': {
            'report_name': '??',
            'date_analyzed': time.strftime('%Y-%m-%d %H:%M'),
            'source': '??',
            'release_date': '??',
            'tlp': tlp,
            'authors': [
                '??'
            ],
            'file_metadata': metadata
        }
    }

    return group_json


def get_time():
    now = datetime.isoformat(datetime.now())
    now = now.replace(':', '_').split('.')[0]
    return now


def processText(text, metadata, outfile):
    '''Process a text
    '''
    outJson = generate_json(text, metadata, tlp=CONFIG_TLP)
    if not outfile:
        print json.dumps(outJson, indent=4)
    else:
        with open(outfile, 'w') as outfile:
            outfile.write(json.dumps(outJson, indent=4))


def processFile(filepath):
    '''Process a File and write output to outfile
    @filename: Input PDF filename

    TODO: use magic to determine file type, instead of keying-off file ext
    '''
    global CONFIG_OUT_FILE
    global CONFIG_OUT_PATH
    global logger
    try:
        logger.debug("- Analyzing File: %s" % (filepath))

        if CONFIG_OUT_FILE and CONFIG_OUT_PATH:
            out_filename = "%s/%s" % (CONFIG_OUT_PATH, CONFIG_OUT_FILE)
        else:
            out_filename = None
            # out_filename = "%s/%s_%s.json" % (CONFIG_OUT_PATH, os.path.basename(filepath), get_time())
        if filepath.endswith('.pdf'):
            text = JagerPDF(filepath).text
        else:
            text = open(filepath).read()
        metadata = file_metadata(filepath)
        processText(text, metadata, out_filename)
        if out_filename:
            logger.debug('- Wrote output to %s' % (out_filename))
        return True
    except IOError as e:
        current_ts = time.strftime("%Y-%m-%d %H:%M")
        logger.error(e)

        with open("error.txt", "a+") as error:
            error.write("%s %s - IOError %s\n" % (current_ts, filepath, e))


def processURL(url):
    global logger
    global CONFIG_OUT_PATH
    urlObj = urlparse(url)
    if urlObj.scheme not in ['http', 'https']:
        logger.warning('Error: Unsupported scheme')
        return False
    try:
        logger.debug("- Analyzing URL: %s" % (url))
        # Many sites will respond with a 4xx if the UA is wget/urllib/etc
        headers = {'User-Agent': 'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)'}
        # disable cert checking (many sites dont have valid certs + speedup )
        r = requests.get(url, verify=False, headers=headers)
        if r.status_code == 200:
            if 'json' in r.headers['content-type']:
                text = r.json()
            elif 'pdf' in r.headers['content-type']:
                temp = tempfile.NamedTemporaryFile(suffix='.pdf')
                temp.file.write(r.text)
                temp.file.close()
                text = JagerPDF(temp.name).text
            else:
                text = r.text
            if CONFIG_OUT_PATH:
                out_filename = "%s/%s_%s.json" % (CONFIG_OUT_PATH, urlObj.netloc, get_time())
            else:
                out_filename = None
            metadata = {'url': url}
            processText(text, metadata, out_filename)
            if out_filename:
                logger.debug('- Wrote output to %s' % (out_filename))
            return True
        else:
            logger.debug('HTTP response : %s' % (r.status_code))

    except Exception as e:
        logger.debug('Error processing URL %s : %s' % (url, e))
    return False


def title():
    ascii_art = """
   __
   \ \  __ _  __ _  ___ _ __
    \ \/ _` |/ _` |/ _ \ '__|
 /\_/ / (_| | (_| |  __/ |
 \___/ \__,_|\__, |\___|_|    IOC Extractor
             |___/

"""
    return ascii_art


# Interface
def main():
    '''Where the initial work happens...'''

    parser = argparse.ArgumentParser(prog=sys.argv[0])

    parser.add_argument("-p", "--pdf", help="Specify an input.", action="store",
                        default=None, type=str, dest="in_pdf", required=False)

    parser.add_argument("-o", "--output", help="Specify an output directory/filename.", action="store",
                        default=None, type=str, dest="out_path", required=False)

    parser.add_argument("-d", "--directory", help="Specify a directory to analyze.",
                        action="store", default=None, type=str, dest="in_directory", required=False)

    parser.add_argument("-u", "--url", help="Analyze webpage.", action="store",
                        default=None, type=str, dest="in_url", required=False)

    parser.add_argument("-t", "--text", help="Analyze text file.",
                        action="store", default=None, type=str, dest="in_text", required=False)

    parser.add_argument("-v", "--verbose", help="if VERBOSE: prints lots of status messages.",
                        action="store_true", dest="verbose", default=False, required=False)

    parser.add_argument("--tlp", help="Configure TLP.",
                        action="store", dest="tlp", default='GREEN', required=False)

    args = parser.parse_args()

    # Setup globals
    global CONFIG_TLP
    global CONFIG_OUT_PATH
    global CONFIG_OUT_FILE
    CONFIG_TLP = args.tlp

    # Setup logger
    #global logger

    logger.debug(title())

    if args.out_path:
        CONFIG_OUT_PATH, CONFIG_OUT_FILE = os.path.split(os.path.abspath(args.out_path))

        # Check if out path exists. If not, create it and check return
        if not os.path.exists(CONFIG_OUT_PATH):
            try:
                os.makedirs(CONFIG_OUT_PATH)
            except OSError as e:
                logger.debug('Error creating output directory %s %s' % CONFIG_OUT_PATH, e)
                exit(1)

    # Start processing command line args
    if args.in_pdf:
        if not os.path.exists(os.path.abspath(args.in_pdf)):
            logger.debug('error: input PDF %s does not exist!' % args.in_pdf)
            exit(1)
        processFile(args.in_pdf)

    elif args.in_url:
        logger.debug("You are trying to analyze: %s and output to %s" % (args.in_url, args.out_path))
        processURL(args.in_url)

    elif args.in_directory:
        # Input directory, expand directory and output to json
        logger.debug("You are trying to analyze all the PDFs in %s and output to %s" % (args.in_directory, args.out_path))

        # An invalid dir or non-existent dir will crash the app
        if os.path.exists(args.in_directory):
            if not os.path.isdir(args.in_directory):
                logger.debug("error: input %s is not a valid directory" % args.in_directory)
                exit(1)
        else:
            logger.debug("error: input directory %s does not exist" % args.in_directory)
            exit(1)

        # Save to a directory, and not a single file
        pool = Pool(processes=cpu_count())
        files = glob.glob('%s/*.pdf' % args.in_directory)
        pool.map(processFile, files)
        pool.close()
        pool.join()

    elif args.in_text:
        # Input of a textfile and output to json
        logger.debug("You are trying to analyze %s and output to %s" % (args.in_text, args.out_path))
        processFile(args.in_text)

    else:
        logger.debug("That set of options won't get you what you need.\n")
        parser.print_help()

    return True

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.debug("User aborted.")
    except SystemExit:
        pass
