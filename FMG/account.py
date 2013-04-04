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

#import os
import shutil
from time import localtime, strftime
import zipfile
import hashlib
#import email
#import mimetypes
import mailbox
#import imaplib
import logging
import re

from accountError import *
from fmg_mailbox import *

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
    retrieved = False # Has mailed been retrieved for this account?

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
    
    txtdir = None
    
    mboxdir = None
    mboxfilename = None
    mboxfilepath = None
    mboxfile = None
    
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
        

## PREPARE FILES AND FOLDERS ##
    def prepDir(self):
        """Prepare file system directories for FMG"""
        logger.debug("Preparing account files and folders")

        # FMG directories
        self.fmgdir = os.path.join(os.path.expanduser("~"), "fmg")
        self.accountdir = os.path.join(self.fmgdir, self.basename)
        
        # Create FMG directory, if it does not exist
        if not os.path.isdir(self.fmgdir):
            logger.debug("Creating FMG directory")
            os.mkdir(self.fmgdir)
        
        # Create account directory
        logger.debug("Creating account directory")
        os.mkdir(self.accountdir)
        
        # Create TEXT output directory
        self.txtdir = os.path.join(self.accountdir, "TEXT")
        if os.path.exists(self.txtdir):
            raise AccountError("TEXT directory exists")
        else:
            try:
                os.mkdir(self.txtdir)
            except Exception as e:
                raise AccountError("Error creating TEXT directory:\n%s" % e)

        # Mbox directory and file
        logger.debug("Setting MBOX directory path and filename: %s", os.path.join(self.accountdir, "MBOX", self.username + ".MBOX"))
        self.mboxdir = os.path.join(self.accountdir, "MBOX")
        self.mboxfilename = self.username + ".MBOX"
        self.mboxfilepath = os.path.join(self.mboxdir, self.username + ".MBOX")
        
        # Create Mbox directory and Mbox-file
        logger.debug("Creating MBOX directory")
        if os.path.isdir(self.mboxdir):
            raise AccountError("Mbox directory exists.")
        else:
            try:
                os.mkdir(self.mboxdir)
            except Exception as e:
                raise AccountError("Error creating Mbox directory:\n%s" % e)

        # Create the MBOX file
        try:
            logger.debug("Creating MBOX file")
            self.mboxfile = mailbox.mbox(self.mboxfilepath)
        except Exception as e:
            logger.error("Failed to create MBOX file")
            logger.debug(e)

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

        # Log in using provided user name and password
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
            
            # Create text output folder for this mailbox
            mailbox_path = os.path.join(self.txtdir, mailbox_name)
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
                self.mailbox_list[mailbox_name] = FMGMailbox(mailbox_name, mailbox_path, item)
            
                # If the current mailbox has children, call recursively
                if "HasChildren" in flags:
                    logger.debug("FMGMailbox has children")
                    response_code, childlist = self.imap_connection.list(mailbox_name)
                    logger.debug("(%s) %s", response_code, childlist)
                    self.buildMailboxList(childlist)
        return
    
    def grabImap(self):
        """Grabs mail from the accounts IMAP server"""
        logger.debug("Grabbing mail from IMAP server")

        # Connect to IMAP Server
        try:
            self.imap_connection = self.connectImap()
        except Exception as e:
            logger.critical("Could not connect to IMAP server")
            logger.debug(e)
            return
        
        # Get all the mailboxes/folders in the IMAP account
        try:
            logger.debug("Getting IMAP current_fmgmailbox list")
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
            
        # Lock the MBOX file before processing mailboxes
        try:
            logger.debug("Locking MBOX file")
            self.mboxfile.lock()
        except Exception as e:
            logger.error("Failed to lock MBOX file")
            logger.debug(e)
            
        # Process all the mailboxes
        for mailbox_name in self.mailbox_list.keys():
            current_fmgmailbox = self.mailbox_list[mailbox_name]
            logger.debug("Processing mailbox %s", mailbox_name)
            try:
                current_fmgmailbox.process(self.imap_connection, self.mboxfile)
            except Exception as e:
                logger.warn("Could not process IMAP mailbox '%s'", mailbox_name)
                logger.debug(e)
                return
            
        # Flush and unlock the MBOX file
        try:
            logger.debug("Flushing and unlocking MBOX file")
            self.mboxfile.flush()
            self.mboxfile.unlock()
        except Exception as e:
            logger.error("Failed to flush and unlock MBOX file")
            logger.debug(e)

        # At this stage, mail in the mailbox has been retrieved
        self.retrieved = True
        
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

### POST PROCESSING ###
    def hashfile(self, filepath):
        logger.debug("Hashing file %s", filepath)
        basepath = os.path.split(filepath)[0]
        filename = os.path.basename(filepath)
        hashfilepath = os.path.join(basepath, filename + ".sha1")
        filehash_sha1 = hashlib.sha1(file(filepath, 'rb').read()).hexdigest()
        logger.debug("Hash (SHA-1): %s", filehash_sha1)
        try:
            logger.debug("Writing hashfile %s", hashfilepath)
            hashfile = open(hashfilepath, 'w')
            hashfile.write(filehash_sha1)
            hashfile.close()
        except Exception as e:
            logger.warn("Failed to write hash file %s", hashfilepath)
            logger.debug(e)
            return False
        return True
    
    def postprocess(self):
        logger.debug("Now post-processing account...")
        
        # Hash
        logger.debug("Hashing MBOX file")
        self.hashfile(self.mboxfilepath)
        
        logger.debug("Hashing text files")
        for root, dirs, files in os.walk(self.txtdir):
            logger.debug("Root: %s", root)
            logger.debug("Dirs: %s", dirs)
            logger.debug("Files to hash: %s", files)
            for f in files:
                logger.debug("Hashing file: %s", os.path.join(root, f))
                self.hashfile(os.path.join(root, f))
        
        # Zip
        logger.debug("Now zipping %s", self.accountdir)
        shutil.make_archive(os.path.join(self.fmgdir, self.basename), "zip", self.accountdir, logger=logger)
        logger.debug("Now hashing zipfile %s", os.path.join(self.fmgdir, self.basename))
        self.hashfile(os.path.join(self.fmgdir, self.basename + ".zip"))
        
        return
