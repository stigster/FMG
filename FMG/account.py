#!/usr/bin/env python -c
# -*- coding: utf-8 -*-

###
# account.py
# Part of FMG
# Forensic Mail Grabber - Uses getmail and some other tools to download email from online providers.
# Version: 0.5 (2013-03-19 08:30 CET)
# by Stig Andersen <stig.andersen@politi.no>
# High Tech Crime Unit, Oslo Police District
###

###
# DISCLAIMER:
# This script will attempt to access the email address to which you provide information.
# Make sure you have legal access to the address before running this script!
# 
# This script is provided free of charge to law enforcement organizations world-wide.
# This script may not be used in conjunction with any form of illegal activity.
#
# No guarantee, warranty or insurance is provided.
# USE AT YOUR OWN RISK!
###

import os.path, os, shutil, sys
import re
from time import localtime, strftime
import zipfile
import hashlib
import email, errno, mimetypes
import imaplib
import logging

from accountError import *

## GLOBAL VARIABLES ##
yes = set(['yes', 'y', 'j', 'ja', ''])
no = set(['no','n', 'nei'])
cancel = set(['q', 'c', 'e', 'quit', 'cancel', 'exit'])

# Prepare logging
logger = logging.getLogger('FMG-log')

## ACCOUNT() ##
class Account():
    """FMG Mail Account Handling Class"""

    ## DEFINE CLASS VARIABLES ##
    retreived = False # Has mailed been retreived for this account?
    tried = False # Has an attempt to retreive mail for this account been made?

    email = None # The email address to grab
    username = None # Email account username
    password = None # Account password

#    servertype = None # Email server protocol type (IMAP, POP), in Getmail format
    serverurl = None # Email server url
    port = None # Email server port
    protocol = None # Email server protocol name
    ssl = None # True if ssl is enabled, false if not

    basename = None
    fmgdir = None
    accountdir = None

    maildirdir = None
    maildirnew = None
    maildirtmp = None
    maildircur = None

    mboxdir = None
    maboxfilename = None

    def __init__(self, email, username, password, serverurl, protocol, port, ssl):
        # Set variables
        self.email = email
        self.username = username
        self.password = password
        self.serverurl = serverurl
        self.port = port
        self.protocol = protocol
        self.ssl = ssl

        # Set account basename
        self.basename = self.email + "_" + strftime("%Y-%m-%d-%H%M%S", localtime())

        return
        

## REMOVE CREATED FOLDERS AND FILES ##
    def cleanup(self):
        """Remove created folders and files"""
        logger.debug("Cleaning up account")
        try:
            shutil.rmtree(self.maildirdir)
            shutil.rmtree(self.mboxdir)
        except Exception as e:
            logger.error("Cleanup failed. %s", "e")
        return

## PREPARE FILES AND FOLDERS ##
    def prepDir(self):
        logger.debug("Preparing account files and folders")
        # Prepare names
        # FMG directories
        self.fmgdir = os.path.join(os.path.expanduser("~"), "fmg")
        self.accountdir = os.path.join(self.fmgdir, self.basename)

        # Maildir directories
        logger.debug("Setting MailDir directory paths")
        self.maildirdir = os.path.join(os.path.expanduser("~"), "Maildir_" + self.username)
        self.maildirnew = os.path.join(self.maildirdir, "new")
        self.maildirtmp = os.path.join(self.maildirdir, "tmp")
        self.maildircur = os.path.join(self.maildirdir, "cur")

        # Mbox directory and file
        logger.debug("Setting MBOX directory path and filename")
        self.mboxdir = os.path.join(os.path.expanduser("~"), "Mbox")
        self.mboxfilename = os.path.join(self.mboxdir, self.username + ".MBOX")

        # Create FMG directory, if it does not exist
        if not os.path.isdir(self.fmgdir):
            logger.debug("Creating FMG directory")
            os.mkdir(self.fmgdir)

        logger.debug("Creating account directory")
        os.mkdir(self.accountdir)

        # Create Maildir directories
        logger.debug("Creating MailDir directories")
        if os.path.isdir(self.maildirdir):
            raise AccountError("Maildir folder exists.")
        else:
            try:
                os.mkdir(self.maildirdir)
                os.mkdir(self.maildirnew)
                os.mkdir(self.maildirtmp)
                os.mkdir(self.maildircur)
            except Exception as e:
                raise AccountError("Error creating Maildir directories:\n%s" % e)

        # Create Mbox directory and Mbox-file
        logger.debug("Creating MBOX directory")
        if os.path.isdir(self.mboxdir):
            raise AccountError("Mbox directory exists.")
        else:
            try:
                os.mkdir(self.mboxdir)
            except Exception as e:
                raise AccountError("Error creating Mbox directory:\n%s" % e)
            logger.debug("Creating MBOX file")
            try:
                mboxfile = open(self.mboxfilename, "w")
                mboxfile.close()
            except Exception as e:
                raise AccountError("Error creating Mbox file:\n%s" % e)

        return

### EMAIL GRABBING ###
    def grabImap(self):
        """Grabs mail from the accounts IMAP server"""
        logger.debug("Grabbing mail from IMAP server")

        # Connect and log in
        if not self.ssl:
            logger.debug("Connecting without SSL")
            try:
                mailbox = imaplib.IMAP4(self.serverurl, self.port)
            except Exception as e:
                logger.error("Could not connect to IMAP server")
                logger.debug(e)
                return
        else:
            logger.debug("Connecting with SSL")
            try:
                mailbox = imaplib.IMAP4_SSL(self.serverurl, self.port)
            except Exception as e:
                logger.error("Could not connect to IMAP SSL server")
                logger.debug(e)
                return

        logger.debug("Logging in")
        try:
            mailbox.login(self.username, self.password)
        except Exception as e:
            logger.error("Could not log on to the account")
            logger.debug(e)
            return

        mailbox_list = mailbox.list()
        print mailbox_list

#        mailbox.select()
#        typ, data = mailbox.search(None, 'ALL')
#        for num in data[0].split():
#            typ, data = mailbox.fetch(num, '(RFC822)')
#            print 'Message %s\n%s\n' % (num, data[0][1])

        # Close selected mailbox and log out
        logger.debug("Closing selected mailbox")
        mailbox.close()

        logger.debug("Logging out")
        try:
            mailbox.logout()
        except Exception as e:
            logger.error("Could not log out from server")
            logger.debug(e)
            
        return

    def grabMail(self):
        """Grabs mail from the accounts server, depending on the server type"""
        logger.debug("Grabbing mail")

        if self.protocol == 'IMAP':
            grabImap(self)

        return


### EMAIL PROCESSING ###

## CREATE A ZIP ARCHIVE CONTAINING ALL ORIGINAL FILES ##
    def zipOriginal(self):
        # Zip everything up
        self.origzipfilename = os.path.join(self.accountdir, self.basename + "_fmg.zip")
        try:
            with zipfile.ZipFile(self.origzipfilename, 'w') as origzip:

                # Add maildir to zip
                origzip.write(self.maildirdir)
                for (path, dirs, files) in os.walk(self.maildirdir):
                    logger.debug("Zipping " + path)
                    for name in files:
                        logger.debug("Zipping file " + os.path.join(path, name))
                        origzip.write(os.path.join(path, name))
                    for name in dirs:
                        logger.debug("Zipping directory " + os.path.join(path, name))
                        origzip.write(os.path.join(path, name))

                # Add mboxdir to zip
                origzip.write(self.mboxdir)
                for (path, dirs, files) in os.walk(self.mboxdir):
                    logger.debug("Zipping " + path)
                    for name in files:
                        logger.debug("Zipping file " + os.path.join(path, name))
                        origzip.write(os.path.join(path, name))
                    for name in dirs:
                        logger.debug("Zipping directory " + os.path.join(path, name))
                        origzip.write(os.path.join(path, name))

        except Exception as e:
            raise AccountError("ERROR: Failed to create FMG Original package.\n%s" % e)


        # Hash the original zip file
        origzip_sha1 = hashlib.sha1(file(self.origzipfilename, 'rb').read()).hexdigest()
        hashfilename = os.path.join(self.accountdir, self.basename + "_fmg.zip.sha1")

        logger.debug("Original ZIP SHA-1: " + origzip_sha1)

        try:
            hashfile = open(hashfilename, 'w')
            hashfile.write(origzip_sha1)
            hashfile.close()
        except Exception as e:
            raise AccountError("ERROR: Failed to write original ZIP Hash file.\n%s" % e)

        return

## COPY THE MBOX FILE ##
    def copymboxfile(self):
        shutil.copyfile(self.mboxfilename, os.path.join(self.accountdir, self.basename + ".MBOX"))

        # Hash the original zip file
        mboxfile_sha1 = hashlib.sha1(file(os.path.join(self.accountdir, self.basename + ".MBOX"), 'rb').read()).hexdigest()
        hashfilename = os.path.join(self.accountdir, self.basename + ".MBOX.sha1")

        logger.debug("MBOX File SHA-1: " + mboxfile_sha1)

        try:
            hashfile = open(hashfilename, 'w')
            hashfile.write(mboxfile_sha1)
            hashfile.close()
        except Exception as e:
            raise AccountError("ERROR: Failed to write MBOX Hash file.\n%s" % e)

        return

## PROCESS THE MAILDIR ##
## DEPRICATED! NEEDS A REWRITE
    def processmaildir(self):
        procdir = os.path.join(self.accountdir, "Mail")
        os.mkdir(procdir)

        for (path, dirs, files) in os.walk(self.maildirnew):
            counter = 1
            for name in files:
                fp = open(os.path.join(path, name))
                msg = email.message_from_file(fp)
                fp.close()

                for part in msg.walk():
                    # multipart/* are just containers
                    if part.get_content_maintype() == 'multipart':
                        continue
                    # Applications should really sanitize the given filename so that an
                    # email message can't be used to overwrite important files
                    filename = part.get_filename()
                    if not filename:
                        ext = mimetypes.guess_extension(part.get_content_type())
                        if not ext:
                            # Use a generic bag-of-bits extension
                            ext = '.bin'
                        filename = 'part-%03d%s' % (counter, ext)
                    counter += 1
                    msgdir = os.path.join(procdir, msg['message-id'])
                    if not os.path.isdir(msgdir):
                        os.mkdir(msgdir)
                    logger.debug("Path: " + os.path.join(msgdir, filename))
                    fp = open(os.path.join(msgdir, filename), 'wb')
                    fp.write(part.get_payload(decode=True))
                    fp.close()

        return

## PROCESS THE RETREIVED MAIL ##
    def processMail(self):
        # ZIP original files and directories to a package
        logger.debug("Zipping original directories")
        self.zipOriginal()

        logger.debug("Copying MBOX-file to account directory")
        self.copymboxfile()

#        logger.debug("Processing maildir into human readable parts")
#        self.processmaildir()

        return
