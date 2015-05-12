#!/usr/bin/env python
# encoding: utf-8
"""
pdf.py

Created by Scott Roberts.
Copyright (c) 2013 TogaFoamParty Studios. All rights reserved.

A module for Jager to extract plain text from PDFs.
"""

import hashlib
import os
import sys
from cStringIO import StringIO

import magic
from pdfminer.converter import TextConverter
from pdfminer.layout import LAParams
from pdfminer.pdfdocument import PDFEncryptionError
from pdfminer.pdfdocument import PDFSyntaxError
from pdfminer.pdfdocument import PDFTextExtractionNotAllowed
from pdfminer.pdfinterp import PDFPageInterpreter
from pdfminer.pdfinterp import PDFResourceManager
from pdfminer.pdfpage import PDFPage


# from pdfminer.pdfparser import PDFSyntaxError

class JagerPDF:

    regex = "\b.*\.pdf\b"
    text = ""

    def __init__(self, pdf_file_path):

        self.path = pdf_file_path
        self.text = self.extractor(self.path)

    def extractor(self, path):
        '''http://stackoverflow.com/questions/5725278/python-help-using-pdfminer-as-a-library'''

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
            pagenos = set()
            for page in PDFPage.get_pages(fp, pagenos, maxpages=maxpages, password=password, caching=caching, check_extractable=True):
                interpreter.process_page(page)
            fp.close()
            device.close()
            str = retstr.getvalue()
            retstr.close()

        except PDFEncryptionError:
            raise

        except PDFTextExtractionNotAllowed:
            raise

        except PDFSyntaxError:
            raise

        except:
            raise

        return str

    def metadata(self):
        print "- Extracting: Source File Metadata"

        hash_sha1 = hashlib.sha1(open(self.path, 'rb').read()).hexdigest()
        filesize = os.path.getsize(self.path)
        filename = os.path.split('/')[-1]
        filetype = magic.from_file(self.path)

        print "- Metadata Generated"

        return {"sha1": hash_sha1, "filesize": filesize, "filename": filename, "filetype": filetype}

    def __str__(self):
        return self.text


def main():
    print "PDF Text Extraction: {}".format(sys.argv[1])
    p = JagerPDF(sys.argv[1])

    print str(p)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print "User aborted."
    except SystemExit:
        pass
