#!/usr/bin/env python -c
# -*- coding: utf-8 -*-

###
# fmg_mailbox.py
# Part of FMG
# Forensic Mail Grabber
# by Stig Andersen <stig.andersen@politi.no>
# Digital Forensics Unit, Oslo Police District
###

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
        logger.debug("Parsing raw email to text")
        maintype = raw_email.get_content_maintype()
        if maintype == 'multipart':
            logger.debug("Email is multipart")
            for part in raw_email.get_payload():
                if part.get_content_maintype() == 'text':
                    return part.get_payload()
        elif maintype == 'text':
            logger.debug("Email is single part")
            return raw_email.get_payload()    
    
    def email_to_txt(self, email_id, email_message):
        """Write email message as text file"""
        email_message_text = self.parse_raw_email(email_message) # Extract the text-part of the message
        if not email_message_text:
            logger.debug("There is no body text in email %s. Setting body text to a blank string.", email_id)
            email_message_text = ""
       
        # Write the email to a text file
        email_filename = email_id + ".txt"
        
        # If the message is multipart, there are attachments
        attachments = [] # Will hold the filename of all attachements, except text/html part.
        if email_message.is_multipart():
            logger.debug("Message is multipart. Extracting attachments")
            load_n = 0
            attachment_n = 0
            for load in email_message.get_payload():
                load_n += 1
                load_maintype = load.get_content_maintype()
                load_subtype = load.get_content_subtype()
                logger.debug("Load %d: Type: %s/%s", load_n, load_maintype, load_subtype)
               
                if load_maintype == 'text' and load_subtype == 'plain':
                    continue
                if load_maintype == 'multipart':
                    continue
               
                attachment_n += 1
               
                # Get attachment filename and make folder for attachments
                attachment_dir = os.path.join(self.txtpath, email_id)
                attachment_filename = load.get_filename()
                if attachment_filename:
                    logger.debug("Found attachment filename: %s", attachment_filename)
                    attachments.append(attachment_filename)
                    # TODO: Sanitize filename
                else:
                    if load_subtype == "html":
                        attachment_filename = email_id + ".html"
                        logger.debug("Multipart is HTML. Filname set to %s", attachment_filename)
                    else:
                        attachment_filename = "Attachment_" + str(attachment_n)
                        attachments.append(attachment_filename)
                        logger.debug("No attachment filename found. Using %s", attachment_filename)
                   
                try:
                    if not os.path.exists(attachment_dir):
                        os.mkdir(attachment_dir)
                except Exception as e:
                    logger.error("Failed to make attachment directory %s", attachment_dir)
                    if email_message['message-id']:
                        logger.debug("Message ID: %s", email_message['message-id'])
                    logger.debug(e)
                   
                # Write the attachment to a file
                try:
                    logger.debug("Writing attachment to file %s", os.path.join(attachment_dir, attachment_filename))
                    open(os.path.join(attachment_dir, attachment_filename), 'wb').write(load.get_payload(decode=True))
                except Exception as e:
                    logger.error("Failed to write attachment to file %s", os.path.join(attachment_dir, attachment_filename))
                    if email_message['message-id']:
                        logger.debug("Message ID: %s", email_message['message-id'])
                    logger.debug(e)        
       
        # Open a file to write to
        try:
            logger.debug("Writing email to text file '%s'", os.path.join(self.txtpath, email_filename))
            f = open(os.path.join(self.txtpath, email_filename), 'w')
        except Exception as e:
            logger.warn("Failed to open email to text file '%s'", os.path.join(self.txtpath, email_filename))
            logger.debug(e)

        # If we got a file in which to store the email
        if f:
            # Write message id to text file
            try:
                logger.debug("Writing message ID to text file")
                f.write("ID: " + email_message['message-id'] + "\n")
            except Exception as e:
                logger.warn("Failed to write message ID to text file '%s'", os.path.join(self.txtpath, email_filename))
                if email_message['message-id']:
                    logger.debug("Message ID: %s", email_message['message-id'])
                logger.debug(e)
                   
            # Write message received to text file
            try:
                logger.debug("Writing message received header to text file")
                f.write("Received: " + email_message['received'] + "\n")
            except Exception as e:
                logger.warn("Failed to write received header to text file '%s'", os.path.join(self.txtpath, email_filename))
                if email_message['message-id']:
                    logger.debug("Message ID: %s", email_message['message-id'])
                logger.debug(e)                   

            # Write message date to text file
            try:
                logger.debug("Writing message date header to text file")
                f.write("Date: " + email_message['date'] + "\n")
            except Exception as e:
                logger.warn("Failed to write date header to text file '%s'", os.path.join(self.txtpath, email_filename))
                if email_message['message-id']:
                    logger.debug("Message ID: %s", email_message['message-id'])
                logger.debug(e)
               
            # Write message from field to text file
            try:
                logger.debug("Writing message from field to text file")
                f.write("From: " + email_message['From'] + "\n")
            except Exception as e:
                logger.warn("Failed to write message from field to text file '%s'", os.path.join(self.txtpath, email_filename))
                if email_message['message-id']:
                    logger.debug("Message ID: %s", email_message['message-id'])
                logger.debug(e)

            # Write message to field to text file
            try:
                logger.debug("Writing message to field to text file")
                f.write("To: " + email_message['To'] + "\n")
            except Exception as e:
                logger.warn("Failed to write message to field to text file '%s'", os.path.join(self.txtpath, email_filename))
                if email_message['message-id']:
                    logger.debug("Message ID: %s", email_message['message-id'])

                logger.debug(e)

            # Write message subject field to text file
            try:
                logger.debug("Writing message subject field to text file")
                f.write("Subject: " + email_message['Subject'] + "\n")
            except Exception as e:
                logger.warn("Failed to write message subject field to text file '%s'", os.path.join(self.txtpath, email_filename))
                if email_message['message-id']:
                    logger.debug("Message ID: %s", email_message['message-id'])
                logger.debug(e)
                
            # If there are attachments, write their names.
            if len(attachments) > 0:
                try:
                    logger.debug("Writing attachment names to text file")
                    f.write("Attachments:\n")
                    for attachment_name in attachments:
                        f.write("\t" + attachment_name + "\n")
                except Exception as e:
                    logger.warn("Failed to write message attachment list to text file '%s'", os.path.join(self.txtpath, email_filename))
                    if email_message['message-id']:
                        logger.debug("Message ID: %s", email_message['message-id'])
                    logger.debug(e)
                    
                        
            # Write message text to text file
            try:
                logger.debug("Writing message text content (%d) to text file", len(email_message_text))
                f.write("Body:\n")
                if len(email_message_text) > 0:
                    f.write(email_message_text)
            except Exception as e:
                logger.warn("Failed to write message text field to text file '%s'", os.path.join(self.txtpath, email_filename))
                if email_message['message-id']:
                    logger.debug("Message ID: %s", email_message['message-id'])
                logger.debug(e)

            # Close the file
            try:
                f.close()
            except Exception as e:
                logger.warn("Failed to close text file '%s'", os.path.join(self.txtpath, email_filename))
                if email_message['message-id']:
                    logger.debug("Message ID: %s", email_message['message-id'])
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
            logger.info("Grabbing %s emails from mailbox folder %s", self.mails, self.name)
            
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
    