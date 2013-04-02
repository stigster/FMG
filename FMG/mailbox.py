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
class Mailbox():
    """FMG Mailbox Class - store information needed to process mailboxes"""
    
    ## DEFINE CLASS VARIABLES ##
    name = None # The name of the mailbox
    path = None # The local path to where content from this mailbox is stored
    item = None # The remote mailbox item
    
    def __init__(self, name, path, item):
        logger.debug("Initializing mailbox item %s, %s, %s", name, path, item)
        self.name = name
        self.path = path
        self.item = item
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
    
    def email_to_txt(self, email_id, email_message, mailbox_path):
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
            logger.debug("Writing email to text file '%s'", os.path.join(mailbox_path, email_filename))
            f = open(os.path.join(mailbox_path, email_filename), 'w')
            if'message-id' in email_message:
                f.write("ID: " + email_message_id + "\n")
            f.write("From: " + email_message_from + "\n")
            f.write("To: " + email_message_to + "\n")
            f.write("Subject: " + email_message_subject + "\n")
            f.write(email_message_text)
            f.close()
        except Exception as e:
            logger.warn("Failed to write email to text file '%s'", os.path.join(mailbox_path, email_filename))
            logger.debug(e)
        return    
    
    def process(self, imap_connection):
    
        # Select the mailbox
        try:
            logger.debug("Selecting IMAP mailbox '%s'", self.name)
            selected = imap_connection.select(self.name, True) # Select the mailbox and set READONLY to True
        except Exception as e:
            logger.warn("Failed to select IMAP Mailbox '%s'", self.name)
            logger.debug(e)
            return
        
        if selected[0] == "OK":
            logger.debug("Selected mailbox contains %s messages", selected[1][0])
        else:
            logger.debug("Could not select mailbox.")
            logger.debug("Server responded: %s", selected)
            return
                
        # TODO: Create MBOX
       
        # Get a list of all the messages in the selected mailbox
        s_result, s_data = imap_connection.search(None, "ALL")
        logger.debug("Mailbox search result: %s", s_result)
        logger.debug("Mailbox search data: %s", s_data)
        for email_id in s_data[0].split():
            logger.debug("Fetching mail #%s", email_id)
            f_result, f_data = imap_connection.fetch(email_id, "(RFC822)") # Fetch the complete email message
            logger.debug("Mailbox fetch result: %s", f_result)
            email_message = email.message_from_string(f_data[0][1])
            
            # TODO: Add the email  message to MBOX
            
            # Write the email to a TXT file
            self.email_to_txt(email_id, email_message, self.path)
            
        # Close selected mailbox
        try:
            logger.debug("Closing selected IMAP mailbox")
            self.imap_connection.close()
        except Exception as e:
                logger.warn("Could not close selected IMAP mailbox")
                logger.debug(e)
    
        return
    