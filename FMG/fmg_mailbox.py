#!/usr/bin/env python -c
# -*- coding: utf-8 -*-

###
# mailbox.py
# Part of FMG
# Forensic Mail Grabber - Uses getmail and some other tools to download email from online providers.
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

'''
Created on 2. apr. 2013

@author: saa025
'''

import logging
import email
import imaplib
import os

## GLOBAL VARIABLES ##
yes = set(['yes', 'y', 'j', 'ja', ''])
no = set(['no','n', 'nei'])
cancel = set(['q', 'c', 'e', 'quit', 'cancel', 'exit'])

# Prepare logging
logger = logging.getLogger('FMG-log')

## ACCOUNT() ##
class FMGMailbox():
    """FMG Mailbox Class - store information needed to process mailboxes"""
    
    ## DEFINE CLASS VARIABLES ##
    name = None # The name of the mailbox
    txtpath = None # The local txtpath to where text content from this mailbox is stored
    item = None # The remote mailbox item
    processed = None # True if the mailbox has been processed, false if not.
    selected = None # True if the mailbox was selected successfully, false if not.
    mails = None # The number of mails found in the mailbox
    
    def __init__(self, name, path, item):
        logger.debug("Initializing mailbox item %s, %s, %s", name, path, item)
        self.name = name
        self.txtpath = path
        self.item = item
        self.processed = False
        self.selected = False
        return
    
    def __str__(self):
        return self.name
    
    def parse_raw_email(self, raw_email):
        """Parse raw email messages."""
        maintype = raw_email.get_content_maintype()
        if maintype == 'multipart':
            for part in raw_email.get_payload():
                if part.get_content_maintype() == 'text':
                    return part.get_payload()
        elif maintype == 'text':
            return raw_email.get_payload()    
    
    def email_to_txt(self, email_id, email_message):
        """Write email message as text file"""
        # Get the basic parts of the email message
        if 'message-id' in email_message:
            email_message_id = email_message['message-id']
        email_message_from = email_message['From']
        email_message_to = email_message['To']
        email_message_subject = email_message['Subject']
        email_message_text = self.parse_raw_email(email_message) # Extract the text-part of the message
        
        # Write the email to a text file
        email_filename = email_id + ".txt"
        try:
            logger.debug("Writing email to text file '%s'", os.path.join(self.txtpath, email_filename))
            f = open(os.path.join(self.txtpath, email_filename), 'w')
            if'message-id' in email_message:
                f.write("ID: " + email_message_id + "\n")
            f.write("From: " + email_message_from + "\n")
            f.write("To: " + email_message_to + "\n")
            f.write("Subject: " + email_message_subject + "\n")
            f.write(email_message_text)
            f.close()
        except Exception as e:
            logger.warn("Failed to write email to text file '%s'", os.path.join(self.txtpath, email_filename))
            logger.debug(e)
        return    
    
    def process(self, imap_connection, mbox):
        """ Process the mailbox by fetching the mail and write it to local output."""
        # Select the mailbox
        try:
            logger.debug("Selecting IMAP mailbox '%s'", self.name)
            selected = imap_connection.select(self.name, True) # Select the mailbox and set READONLY to True
        except Exception as e:
            logger.warn("Failed to select IMAP mailbox '%s'", self.name)
            logger.debug(e)
            return
        
        # If the mailbox was selected ok, process it.
        if selected[0] == "OK":
            self.selected = True
            self.mails = selected[1][0]
            logger.debug("Selected mailbox contains %s messages", self.mails)
            
            # Get a list of all the messages in the selected mailbox
            s_result, s_data = imap_connection.search(None, "ALL")
            logger.debug("Mailbox search result: %s", s_result)
            logger.debug("Mailbox search data: %s", s_data)
            n = 0
            for email_id in s_data[0].split():
                logger.debug("Fetching mail #%s", email_id)
                f_result, f_data = imap_connection.fetch(email_id, "(RFC822)") # Fetch the complete email message
                logger.debug("Mailbox fetch result: %s", f_result)
                email_message = email.message_from_string(f_data[0][1])
                
                # Add the email message to the MBOX
                try:
                    logger.debug("Adding email #%s from mailbox %s to MBOX", email_id, self.name)
                    mbox.add(email_message)
                except Exception as e:
                    logger.warn("Failed to add email #%s from mailbox %s to MBOX", email_id, self.name)
                    logger.debug(e)
                
                # Write the email to a TXT file
                self.email_to_txt(email_id, email_message)            
                
                n += 1
            logger.debug("Expected %s, processed %s emails", self.mails, n)
            
            # Close selected mailbox
            logger.debug("Closing selected IMAP mailbox")
            imap_connection.close()
        else:
            logger.debug("Could not select mailbox.")
            logger.debug("Server responded: %s", selected)

        # Tag the mailbox as processed
        self.processed = True
        return
    