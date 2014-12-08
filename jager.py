#!/usr/bin/env python
# encoding: utf-8
"""
jager.py

Created by Scott Roberts.
Copyright (c) 2013 TogaFoamParty Studios. All rights reserved.
"""

from optparse import OptionParser
import re
import json
import time
import hashlib
import os
import requests
import magic

from pdfminer.pdfinterp import PDFResourceManager, PDFPageInterpreter
from pdfminer.converter import TextConverter
from pdfminer.layout import LAParams
from pdfminer.pdfpage import PDFPage
from cStringIO import StringIO
import bs4

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

# Indicators
re_ipv4 = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", re.I | re.S | re.M)
re_email = re.compile("\\b[A-Za-z0-9_.]+@[0-9a-z.-]+\\b", re.I | re.S | re.M)
re_domain = re.compile("([a-z0-9-_]+\\.){1,4}(com|aero|am|asia|au|az|biz|br|ca|cat|cc|ch|co|coop|cx|de|edu|fr|gov|hk|info|int|ir|jobs|jp|kr|kz|me|mil|mobi|museum|name|net|nl|nr|org|post|pre|ru|tel|tk|travel|tw|ua|uk|uz|ws|xxx)", re.I | re.S | re.M)
re_cve = re.compile("(CVE-(19|20)\\d{2}-\\d{4})", re.I | re.S | re.M)
re_url = re.compile(ur'(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:\'".,<>?\xab\xbb\u201c\u201d\u2018\u2019]))')

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


# Text Extractors:
def pdf_text_extractor(path):
    '''http://stackoverflow.com/questions/5725278/python-help-using-pdfminer-as-a-library'''

    print "- Extracting: PDF Text - %s" % (path.split("/")[-1])

    try:
        rsrcmgr = PDFResourceManager()
        retstr = StringIO()
        codec = 'utf-8'
        laparams = LAParams()
        device = TextConverter(rsrcmgr, retstr, codec=codec, laparams=laparams)
        fp = file(path, 'rb')
        interpreter = PDFPageInterpreter(rsrcmgr, device)
        password = ""
        maxpages = 0
        caching = True
        pagenos=set()
        for page in PDFPage.get_pages(fp, pagenos, maxpages=maxpages, password=password,caching=caching, check_extractable=True):
            interpreter.process_page(page)
        fp.close()
        device.close()
        str = retstr.getvalue()
        retstr.close()
        return str

    except:
        # CATCH Text Extraction Failure
        # pdfminer.pdfdocument.PDFTextExtractionNotAllowed: Text extraction is not allowed: <open file '/Users/scottjroberts/Documents/src/APTnotes/2014/h12756-wp-shell-crew.pdf', mode 'rb' at 0x10bc01e40>
        raise

    print doc.info


def www_text_extractor(target):

    response = requests.get(target)
    soup = bs4.BeautifulSoup(response.text)
    [s.extract() for s in soup('script')]
    return soup.body.get_text()


# Meta Data
def file_metadata(path, type):
    print "- Extracting: Source File Metadata"

    hash_sha1 = hashlib.sha1(open(path, 'rb').read()).hexdigest()
    filesize = os.path.getsize(path)
    filename = path.split('/')[-1]
    filetype = magic.from_file(path)

    return {"sha1": hash_sha1, "filesize": filesize, "filename": filename, "filetype": filetype}


# Data Extractors
def extract_hashes(t):
    print "- Extracting: Hashes"

    md5s = list(set(re.findall(re_md5, t)))
    sha1s = list(set(re.findall(re_sha1, t)))
    sha256s = list(set(re.findall(re_sha256, t)))
    sha512s = list(set(re.findall(re_sha512, t)))
    ssdeeps = list(set(re.findall(re_ssdeep, t)))

    print " - %s MD5s detected." % len(md5s)
    print " - %s SHA1s detected." % len(sha1s)
    print " - %s SHA256s detected." % len(sha256s)
    print " - %s SHA512s detected." % len(sha512s)
    print " - %s ssdeeps detected." % len(ssdeeps)

    return {"md5s": md5s, "sha1s": sha1s, "sha256": sha256s, "sha512": sha512s, "ssdeep": ssdeeps}


def extract_emails(t):
    print "- Extracting: Email Addresses"

    emails = list(set(re.findall(re_email, t)))
    emails.sort()

    print " - %d email addresses detected." % (len(emails))

    return emails


def extract_ips(t):
    print "- Extracting: IPv4 Addresses"

    ips = re.findall(re_ipv4, t)
    ips = list(set(ips))
    ips.sort()

    print " - %d IPv4 addresses detected." % len(ips)

    return {"ipv4addresses": ips, "ipv6addresses": []}


def extract_cves(t):
    print "- Extracting: CVE Identifiers"

    cves = re.findall(re_cve, t)
    cves = list(set(cves))

    cves = [cve[0] for cve in cves]

    print " - %d CVE identifiers detected." % len(cves)

    return cves


def extract_domains(t):
    print "- Extracting: Domains"

    domains = []

    t = t.split("\n")

    for line in t:
        hit = re.search(re_domain, line)
        if re.search(re_domain, line):
            domains.append(hit.group().lower())

    domains = list(set(domains))
    domains.sort()

    print " - %d domains detected." % len(domains)

    return domains


def extract_urls(t):
    print "- Extracting: URLs"
    urls = re.findall(re_url, t)
    # eliminate repeats
    urls = list(set(urls))
    urls.sort()

    print " - %d URLs detected." % len(urls)

    return urls


def extract_filenames(t):
    print "- Extracting: File Names"

    docs = list(set(["".join(doc) for doc in re.findall(re_doc, t)]))
    exes = list(set(["".join(item) for item in re.findall(re_exe, t)]))
    webs = list(set(["".join(item) for item in re.findall(re_web, t)]))
    zips = list(set(["".join(item) for item in re.findall(re_zip, t)]))
    imgs = list(set(["".join(item) for item in re.findall(re_img, t)]))
    flashes = list(set(["".join(item) for item in re.findall(re_flash, t)]))

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
def generate_json(text, metadata):

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
            "authors": [
                "??"
            ],
            "file_metadata": metadata
        }
    }

    return group_json


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

    parser = OptionParser(usage="usage: %prog [options] input (-p, -d, -u, -t) arguement -o/--out filename")
    parser.add_option("-p", "--pdf",
                      action="store",
                      type="string",
                      dest="in_pdf",
                      default=None,
                      help="Specify an input.")
    parser.add_option("-o", "--out",
                      action="store",
                      type="string",
                      dest="out_path",
                      default="output.json",
                      help="Specify an output.")
    parser.add_option("-d", "--directory",
                      action="store",
                      type="string",
                      dest="in_directory",
                      default=None,
                      help="WIP: Specify a directory to analyze.")
    parser.add_option("-u", "--url",
                      action="store",
                      type="string",
                      dest="in_url",
                      default=None,
                      help="WIP: Analyze webpage.")
    parser.add_option("-t", "--text",
                      action="store",
                      type="string",
                      dest="in_text",
                      default=None,
                      help="NOT IMPLIMENTED: Analyze textfile.")

    (options, args) = parser.parse_args()

    if options.in_pdf and options.out_path:
        # Input of a PDF out to JSON
        out_file = open(os.path.abspath(options.out_path), 'w')
        in_file = os.path.abspath(options.in_pdf)
        metadata = file_metadata(in_file, "PDF")

        pdftext = pdf_text_extractor(in_file)
        outjson = json.dumps(generate_json(pdftext, metadata), indent=4)

        out_file.write(outjson)
        out_file.close()

    elif options.in_url and options.out_path:
        # Input of a website out to JSON
        print "WIP: You're trying to analyze: %s and output to %s" % (options.in_url, options.out_path)

        r = requests.get(options.in_url)

    elif options.in_directory and options.out_path:
        # Input of a directory, expand directory, and output to json
        print "WIP: You are trying to analyze all the PDFs in %s and output to %s" % (options.in_directory, options.out_path)

        for root, dirs, files in os.walk(os.path.abspath(options.in_directory)):
            for filepath in files:
                if filepath.endswith(".pdf"):
                    print "- Analyzing File: %s" % (filepath)
                    out_filename = "%s/%s.json" % (options.out_path, filepath.split('/')[-1].split(".")[0])
                    out_file = open(out_filename, 'w')
                    filepath = os.path.join(root,filepath)
                    metadata = file_metadata(filepath, "PDF")
                    out_json = generate_json(filepath, metadata)
                    out_file.write(json.dumps(out_json), indent=4)
                    out_file.close()

    elif options.in_text and options.out_path:
        # Input of a textfile and output to json
        print "NOT IMPLEMENTED: You are trying to analyze %s and output to %s" % (options.in_text, options.out_path)

    else:
        print "That set of options won't get you what you need.\n"
        parser.print_help()

    return True


def test_main():
    url = "http://contagiodump.blogspot.com/2014/07/cz-solution-ltd-signed-samples-of.html"
    print "Trying to Text Extract %s" % url
    print generate_json(www_text_extractor(url), {'source', url})


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print "User aborted."
    except SystemExit:
        pass
