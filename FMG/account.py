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

import os, shutil
from time import localtime, strftime
import zipfile
import hashlib
import email, mimetypes
import imaplib
import logging
import re

from accountError import *
from mailbox import *

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
    
    currentMailbox = None # Used to track mailbox processing
    currentMailboxHasChildren = None # Used to track mailbox processing

    maildirdir = None
    maildirnew = None
    maildirtmp = None
    maildircur = None

    mboxdir = None
    maboxfilename = None
    
    imap_connection = None

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
        
        # Prepare other variables
        self.mailbox_list = {}
        self.imap_connection = None

        return
        

## REMOVE CREATED FOLDERS AND FILES ##
    def cleanup(self):
        """Remove created folders and files"""
        logger.debug("Cleaning up account")
        try:
            shutil.rmtree(self.maildirdir)
            shutil.rmtree(self.mboxdir)
        except Exception as e:
            logger.error("Cleanup failed. %s", e)
        return

## PREPARE FILES AND FOLDERS ##
    def prepDir(self):
        """Prepare file system directories for FMG"""
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
    def connectImap(self):
        """Connect to the accounts IMAP server and log on the user account with provided password."""
        # Connect to IMAP Server
        if not self.ssl: # ... without SSL
            logger.debug("Connecting without SSL")
            try:
                imap_connection = imaplib.IMAP4(self.serverurl, self.port)
            except Exception as e:
                logger.error("Could not connect to IMAP server")
                logger.debug(e)
                return None
        else: # ... or with SSL
            logger.debug("Connecting with SSL")
            try:
                imap_connection = imaplib.IMAP4_SSL(self.serverurl, self.port)
            except Exception as e:
                logger.error("Could not connect to IMAP SSL server")
                logger.debug(e)
                return None

        # Log in using provided username and password
        try:
            logger.debug("Logging in user '%s'", self.username)
            imap_connection.login(self.username, self.password)
        except Exception as e:
            logger.error("Could not log on to the user account '%s'", self.username)
            logger.debug(e)
            return None
        
        return imap_connection        

    def parse_mailboxlist(self, mailbox_list_item):
        """Parse the IMAP account list of mailboxes/folders."""
        logger.debug("Parsing mailbox list item '%s'", mailbox_list_item)
        list_response_pattern = re.compile(r'\((?P<flags>.*?)\) "(?P<delimiter>.*)" (?P<name>.*)')
        
        flags, delimiter, mailbox_name = list_response_pattern.match(mailbox_list_item).groups()
        mailbox_name = mailbox_name.strip('"')
        
        return (flags, delimiter, mailbox_name)
    
    def buildMailboxList(self, mailboxlist):
        """Builds a list of all mailboxes to be processed"""
        for item in mailboxlist:
            flags, delimiter, mailbox_name = self.parse_mailboxlist(item)
            flags = re.sub("\\\\", "", flags) # Remove \ from flags string
            flags = flags.split() # Make a list of the flags
            logger.debug("Processing mailbox item %s", item)
            
            # Create folder for this mailbox
            mailbox_path = os.path.join(self.accountdir, mailbox_name)
            if not os.path.exists(mailbox_path):
                try:
                    logger.debug("Creating mailbox folder '%s'", mailbox_path)
                    os.mkdir(mailbox_path)
                except Exception as e:
                    logger.warn("Could not create mailbox folder '%s'", mailbox_path)
                    logger.debug(e)
                    
            # Add a mailbox object to the list of mailboxes and add relevant information
            if not mailbox_name in self.mailbox_list:
                logger.debug("Adding %s to mailbox list", mailbox_name)
                logger.debug("Path for mailbox %s set to %s", mailbox_name, mailbox_path)
                self.mailbox_list[mailbox_name] = Mailbox(mailbox_name, mailbox_path, item)
            
                # If the current mailbox has children, call recursively
                if "HasChildren" in flags: #re.search("HasChildren", flags):
                    logger.debug("Mailbox has children")
                    response_code, childlist = self.imap_connection.list(mailbox_name)
                    logger.debug("(%s) %s", response_code, childlist)
                    self.buildMailboxList(childlist)
        return
    
    def grabImap(self):
        """Grabs mail from the accounts IMAP server"""
        logger.debug("Grabbing mail from IMAP server")

        # Connect to IMAP Server
        # TODO: Add try - except block
        try:
            self.imap_connection = self.connectImap()
        except Exception as e:
            logger.critical("Could not connect to IMAP server")
            logger.debug(e)
            return
        
        # Get all the mailboxes/folders in the IMAP account
        try:
            logger.debug("Getting IMAP mailbox list")
            response_code, remote_mailbox_list = self.imap_connection.list()
            logger.debug(remote_mailbox_list)
        except Exception as e:
            logger.critical("Could not list IMAP mailboxes")
            logger.debug(e)
            logger.debug("Logging out")
        
        # Build a list of all mailboxes in the IMAP account (recursively - make sure we get everything)
        if response_code == 'OK':
            logger.debug("Building list of mailboxes in IMAP account")
            self.buildMailboxList(remote_mailbox_list)
            logger.debug("List created (%d items)", len(self.mailbox_list))
            logger.debug(self.mailbox_list)
            
        # Process all the mailboxes            
        for mailbox_name in self.mailbox_list.keys():
            mailbox = self.mailbox_list[mailbox_name]
            logger.debug("Processing mailbox %s", mailbox_name)
            try:
                mailbox.process(self.imap_connection)
            except Exception as e:
                logger.warn("Could not process IMAP mailbox '%s'", mailbox_name)
                logger.debug(e)
                return

        # Log out from IMAP connection
        try:
            logger.debug("Logging out from IMAP Connection")
            self.imap_connection.logout()
        except Exception as e:
            logger.warn("Could not log out from server")
            logger.debug(e)
            
        return

    def grabMail(self):
        """Grabs mail from the accounts server, depending on the server type"""
        logger.debug("Grabbing mail")

        if self.protocol == 'IMAP':
            self.grabImap()

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
