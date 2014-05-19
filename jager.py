#!/usr/bin/env python
# encoding: utf-8
"""
Starter_Script_With_Args.py

Created by Scott Roberts.
Copyright (c) 2013 TogaFoamParty Studios. All rights reserved.
"""

from optparse import OptionParser
from PyPDF2 import PdfFileReader
import re

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

def extract_pdf_text(pdf_path = "/Users/sroberts/Desktop/fireeye-operation-saffron-rose.pdf"):
    """Just some testing to get started"""

    pdf = PdfFileReader(open(pdf_path, "rb"))

    print pdf.getDocumentInfo()

    pdf_text = [page.extractText().lower() for page in pdf.pages]

    return pdf_text

def extract_hashes(t):
    unified_text = " ".join(t)

    md5s = re.findall("[a-f0-9]{32}", unified_text)
    sha1s = re.findall("[a-f0-9]{40}", unified_text)

    return {"md5s": md5s, "sha1s": sha1s}

def extract_emails(t):

    emails = re.findall("[A-Z0-9._%+-]+@[A-Z0-9.-]+\.(?:[A-Z]{2}|com|org|net|edu|gov|mil|biz|info|mobi|name|aero|asia|jobs|museum)", " ".join(t))

    print {"emails": emails}

# def foo():
#     return "foo function called"
#
# def bar():
#     return "bar function called"

def main():

    pdf_path = "/Users/sroberts/Desktop/fireeye-operation-saffron-rose.pdf"

    # parser = OptionParser(usage="usage: %prog [options] filepath")
    # parser.add_option("-f", "--foo",
    #                   action="store",
    #                   type="string",
    #                   dest="foo_dest",
    #                   default=None,
    #                   help="You picked option foo!")
    # parser.add_option("-b", "--bar",
    #                   action="store",
    #                   type="string",
    #                   dest="bar_dest",
    #                   default=None,
    #                   help="You picked option bar!")
    #
    # (options, args) = parser.parse_args()

    #Uncomment to enforce at least one final argument
    #if len(args) != 1:
        #parser.error("You didn't specify a target path.")
        #return False

    # if options.foo_dest:
    #   print foo()
    # else:
    #   print "Foo Dest: Blank"
    #
    # if options.bar_dest:
    #   print bar()
    # else:
    #   print "Bar Dest: Blank"

    pdf_text = extract_pdf_text(pdf_path)


    print extract_hashes(pdf_text)
    print extract_emails(pdf_text)

    return True

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print "User aborted."
    except SystemExit:
        pass
    #except:
        #crash()