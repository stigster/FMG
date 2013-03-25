#!/usr/bin/env python -c
# -*- coding: utf-8 -*-

###
# fmg.py
# Forensic Mail Grabber - Uses getmail and some other tools to download email from online providers.
# Version: 0.7 (2013-03-23 13:30 CET)
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


# IMPORT SYSTEM PACKAGES #
import logging  # @UnresolvedImport
import os.path
import argparse  # @UnresolvedImport
from time import localtime, strftime # (strftime("%Y-%m-%d-%H%M%S", localtime()))
import re  # @UnresolvedImport

# IMPORT FMG PACKAGES #
from account import Account
from accountError import *

# GLOBALS #
yes = set(['yes', 'y', 'ja', 'j', ''])
no = set(['no', 'n', 'nei'])
cancel = set(['cancel', 'c'])


class Fmg():
    """FMG - Forensic Mail Grabber base class"""

    # VARIABLES #
    logger = None

    email = None
    username = None
    password = None
    serverurl = None
    port = None
    protocol = None

    imap = None
    pop = None
    mapi = None

    ssl = None
    nossl = None

    debug = None
    verbose = None
    quiet = None

    dry = None
    force = None

    acc = None

    # SETUP LOGGING #
    def logSetup(self):
        # Create the logger
        self.logger = logging.getLogger('FMG-log')
        if args.debug:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)

        # Define log formats
        fileformatter = logging.Formatter("%(asctime)s %(levelname)s: %(message)s")
        consoleformatter = logging.Formatter("%(message)s")
        
        # Log to Console
        clog = logging.StreamHandler()
        clog.setFormatter(consoleformatter)
        if self.debug:
            clog.setLevel(logging.DEBUG)
        elif self.verbose:
            clog.setLevel(logging.INFO)
        elif self.quiet:
            clog.setLevel(logging.CRITICAL)
        else:
            clog.setLevel(logging.WARNING)
        self.logger.addHandler(clog)

        # Make sure there is an fmg directory to log to
        if not os.path.exists(os.path.join(os.path.expanduser("~"), "fmg")):
            os.mkdir(os.path.join(os.path.expanduser("~"), "fmg"))

        # Log to file (masterlog)
        masterlog_path = os.path.join(os.path.expanduser("~"), "fmg")
        masterlog_filename = "fmg.log"
        masterlog = logging.FileHandler(os.path.join(masterlog_path, masterlog_filename))
        masterlog.setLevel(logging.INFO)
        masterlog.setFormatter(fileformatter)
        self.logger.addHandler(masterlog)

        # Runlog
        runlog_path = masterlog_path
        runlog_filename = "fmg_%s.log" % (strftime("%Y-%m-%d-%H%M%S_%Z", localtime()))
        runlog = logging.FileHandler(os.path.join(runlog_path, runlog_filename), mode='w')
        runlog.setLevel(logging.INFO)
        runlog.setFormatter(fileformatter)
        self.logger.addHandler(runlog)

        # Debuglog
        if self.debug:
            debuglog = logging.FileHandler("fmg_debug.log")
            debuglog.setLevel(logging.DEBUG)
            self.logger.addHandler(debuglog)

        return


    # GET AND VALIDATE INPUT #
    def getInput(self):
        """VALIDATE INPUT, SET CORRECT VALUES, PROMPT FOR MISSING VALUES"""
    
        # Validate and set email address
        self.logger.debug("Setting email address")
        if self.email:
            self.logger.debug("Using email from cmd.line argument")
        elif not self.force:
            self.logger.debug("Prompting for email address")

            while True:
                self.email = raw_input("Email address (Type 'c' to cancel): ")
                self.logger.debug("Email address entered: %s", self.email)
                if re.search(r"[A-Z0-9._%+-]+@(?:[A-Z0-9-]+\.)+[A-Z]{2,4}", self.email, re.IGNORECASE):
                    self.logger.debug("Validated email address by regular expression")
                    break
                elif self.email in cancel:
                    self.logger.info("Email address input cancelled")
                    self.logger.info("----- Terminating FMG -----")
                    exit(1)
                else:
                    print "Not a valid email address. Try again!"
        else:
            self.logger.critical("Forced to terminate: No email address!")
            self.logger.info("----- Terminating FMG -----")
            exit(1)

    # Validate and set username
        self.logger.debug("Setting username")
        if self.username:
            self.logger.debug("Using username from cmd.line argument")
        elif not self.force:
            self.logger.debug("Prompting for username verification")
            email_re = re.match(r"(.+)@(.+)", self.email)
            input_txt = "Use '%s' as username? [YES/No/Cancel]: " % email_re.group(1)
            while True:
                verify_username = raw_input(input_txt)
                if verify_username in yes:
                    self.logger.debug("Username verified by user")
                    self.username = email_re.group(1)
                    break
                elif verify_username in no:
                    self.logger.debug("Prompting for username")
                    n = 0
                    while True:
                        self.username = raw_input("Username: ")
                        if not self.username == "":
                            self.logger.debug("A username was entered")
                            break
                        else:
                            n = n + 1
                            if n == 3:
                                self.logger.debug("Terminating after 3 prompts for username")
                                self.logger.critical("No username found")
                                self.logger.info("----- Terminating FMG -----")
                                exit(1)
                            print "No username entered. Try again (%d/3)." % n
                elif verify_username in cancel:
                    self.logger.info("Username verification cancelled")
                    self.logger.info("----- Terminating FMG -----")
                    exit(1)
                else:
                    print "Invalid selection, try again!"
        else:
            self.logger.info("Assuming username from email address")
            email_re = re.match(r"(.+)@(.+)", self.email)
            self.username = email_re.group(1)
            if self.username == "":
                self.logger.critical("Forced to terminate: No username!")
                self.logger.info("----- Terminating FMG -----")
                exit(1)

        # Validate and set password (NOTE: Password is not validated against the server. Only input validation.)
        self.logger.debug("Setting passord")
        if self.password:
            self.logger.debug("Using password from cmd.line argument")
            self.password = args.password
        elif not self.force:
            self.logger.debug("Prompting for password")
            self.password = raw_input("Password: ")
            if not self.password == "":
                self.logger.debug("A password was entered")
            else:
                self.logger.critical("No password entered")
                self.logger.info("----- Terminating FMG -----")
                exit(1)
        else:
            self.logger.critical("Forced to terminate: No password!")
            self.logger.info("----- Terminating FMG -----")
            exit(1)

        # Validate and set server URL
        self.logger.debug("Setting server url")
        if self.serverurl:
            self.logger.debug("Using server URL from cmd.line argument")
            self.serverurl = args.server
        elif not self.force:
            self.logger.debug("Prompting for server URL")
            
            if not email_re:
                self.logger.debug("Getting server url from email address")
                email_re = re.match(r"(.+)@(.+)", self.email)
    
                verify_url = False
                if self.imap or self.pop:
                    if self.imap:
                        self.logger.debug("Protocol is IMAP, completing server url accordingly")
                        self.serverurl = "imap." + email_re.group(2)
                    elif self.pop:
                        self.logger.debug("Protocol is POP, completing server url accordingly")
                        self.serverurl = "pop." + email_re.group(2)

                    input_txt = "Use %s as server url? [YES/No/Cancel]: " % self.serverurl
        
                    while True:
                        verify_url = raw_input(input_txt)
                        if verify_url in yes:
                            self.logger.debug("Server url verified by user")
                            verify_url = True
                            break
                        elif verify_url in no:
                            verify_url = False
                        elif verify_url in cancel:
                            self.logger.info("Server URL input cancelled")
                            self.logger.info("----- Terminating FMG -----")
                            exit(1)
                        else:
                            print "Invalid input, try again"

                if not verify_url:
                    n = 0
                    while True:
                        self.serverurl = raw_input("Server URL: ")
                        if not self.serverurl == "":
                            self.logger.debug("A server url was entered")
                            break
                        else:
                            n = n + 1
                            if n == 3:
                                self.logger.debug("Terminating after 3 prompts for server url")
                                self.logger.critical("No server URL found")
                                self.logger.info("----- Terminating FMG -----")
                                exit(1)
                            print "No server URL was entered. Try again (%d/3)." % n
        else:
            self.logger.debug("Forced to assume default server URL")

            if not email_re:
                self.logger.debug("Getting server url from email address")
                email_re = re.match(r"(.+)@(.+)", self.email)

            if self.protocol == 'IMAP':
                self.logger.debug("Protocol is IMAP, completing server url accordingly")
                self.serverurl = "imap." + email_re.group(2)
            elif self.protocol == 'POP':
                self.logger.debug("Protocol is POP, completing server url accordingly")
                self.serverurl = "pop." + email_re.group(2)

        # Validate and set protocol
        self.logger.debug("Setting protocol")
        if self.imap:
            self.logger.debug("Protocol 'IMAP' set as cmd.line argument")
            self.protocol = 'IMAP'
        elif self.pop:
            self.logger.debug("Protocol 'POP' set as cmd.line argument")
            self.protocol = 'POP'
        elif not self.force:
            self.logger.debug("Prompting for protocol selection")
        # TODO: Check server url for protocol information
            imap = set(['imap', 'i', ''])
            pop = set(['pop', 'p'])
            while True:
                select_protocol = raw_input("Select server protocol type [IMAP, Pop] (Type 'c' to cancel'): ").lower()
                if select_protocol in imap:
                    self.logger.debug("Setting protocol to 'IMAP'")
                    self.protocol = 'IMAP'
                    break
                elif select_protocol in pop:
                    self.logger.debug("Setting protocol to 'POP'")
                    self.protocol = 'POP'
                    break
                elif select_protocol in cancel:
                    self.logger.info("Protocol selection cancelled.")
                    self.logger.info("----- Terminating FMG -----")
                    exit(1)
                else:
                    print "Invalid selection, try again!"
        else:
            self.logger.info("Assuming default protocol IMAP")
            # TODO: Check server url for protocol information
            self.protocol = 'IMAP'

        # Validate and set SSL
        self.logger.debug("Setting SSL")
        if self.ssl:
            self.logger.debug("SSL set from cmd.line argument")
            self.ssl = True
        elif self.nossl:
            self.logger.debug("NO-SSL set at cmd.line argument")
            self.ssl = False
        elif not self.force:
            self.logger.debug("Prompting for SSL")
            while True:
                verify_ssl = raw_input("Use SSL encryption? [YES/No/Cancel]: ")
                if verify_ssl in yes:
                    self.logger.debug("User selected SSL ON")
                    self.ssl = True
                    break
                elif verify_ssl in no:
                    self.logger.debug("User selected SSL OFF")
                    self.ssl = False
                    break
                elif verify_ssl in cancel:
                    self.logger.info("SSL selection cancelled")
                    self.logger.info("----- Terminating FMG -----")
                    exit(1)
                else:
                    print "Invalid selection, try again!"
        else:
            self.logger.debug("Forced to assume default, assuming SSL true")
            self.ssl = True

        # Validate and set server port
        self.logger.debug("Setting server port")
        if self.port:
            self.logger.debug("Using server port from cmd.line argument")
            self.port = args.port
        elif not self.force:
            self.logger.debug("Prompting for server port")

            if self.protocol == 'IMAP' and self.ssl:
                self.logger.debug("Protocol is IMAP and SSL is set. Suggesting default IMAPS port")
                self.port = "993"
            elif self.protocol == 'IMAP' and not self.ssl:
                self.logger.debug("Protocol is IMAP and SSL it NOT set. Suggesting default IMAP port")
                port = "143"
            elif self.protocol == 'POP' and self.ssl:
                self.logger.debug("Protocol is POP and SSL is set. Suggesting default secure POP3 (SSL-POP) port")
                self.port = "995"
            elif self.protocol == 'POP' and not self.ssl:
                self.logger.debug("Protocol is POP and SSL is NOT set. Suggesting default POP3 port")
                self.port = "110"

            input_txt = "Use %s as server port? [YES/No/Cancel]: " % port
            while True:
                verify_port = raw_input(input_txt)
                if verify_port in yes:
                    self.logger.debug("Server port verified by user")
                    break
                elif verify_port in no:
                    n = 0
                    while True:
                        self.port = raw_input("Server port: ")
                        if not self.port == "":
                            self.logger.debug("A server port was entered")
                            break
                        else:
                            n = n + 1
                            if n == 3:
                                self.logger.debug("Terminating after 3 prompts for server port")
                                self.logger.critical("No server port found")
                                self.logger.info("----- Terminating FMG -----")
                                exit(1)
                            print "No server port was entered. Try again (%d/3)." % n
                elif verify_port in cancel:
                    self.logger.info("Server port input cancelled")
                    self.logger.info("----- Terminating FMG -----")
                    exit(1)
                else:
                    print "Invalid input, try again"
        else:
            self.logger.debug("Forced to assume default server port")

            if self.protocol == 'IMAP' and self.ssl:
                self.logger.debug("Protocol is IMAP and SSL is set. Suggesting default IMAPS port")
                self.port = "993"
            elif self.protocol == 'IMAP':
                self.logger.debug("Protocol is IMAP and SSL it NOT set. Suggesting default IMAP port")
                self.port = "143"
            elif self.protocol == 'POP' and self.ssl:
                self.logger.debug("Protocol is POP and SSL is set. Suggesting default secure POP3 (SSL-POP) port")
                self.port = "995"
            elif self.protocol == 'POP':
                self.logger.debug("Protocol is POP and SSL is NOT set. Suggesting default POP3 port")
                self.port = "110"

        return

    # FMG INIT #
    def __init__(self, email, username, password, server, port, imap, mapi, pop, ssl, nossl, debug, verbose, quiet, dry, force):
        email = email
        username = username
        password = password
        server = server
        port = port
        imap = imap
        mapi = mapi
        pop = pop
        ssl = ssl
        nossl = nossl
        debug = debug
        verbose = verbose
        quiet = quiet
        dry = dry
        force = force

        self.logSetup()

        # Log program start header
        self.logger.info("----- FMG Forensic Mail Grabber -----")
        self.logger.info(ver)
        self.logger.info(strftime("%Y-%m-%d-%H%M%S", localtime()))

        # Log program execution mode
        if self.dry:
            self.logger.info("THIS IS A DRY-RUN")
        if self.force:
            self.logger.info("FMG Running in FORCED mode!")
            
        return

    # FMG MAIN #
    def main(self):
        # Get and/or validate user input
        self.getInput()

        # Create an Account object on which to operate
        self.logger.debug("Creating Account object")
        try:
            self.acc = Account(self.email, 
                               self.username, 
                               self.password, 
                               self.serverurl, 
                               self.protocol, 
                               self.port, 
                               self.ssl)
        except AccountError as ae:
            self.logger.critical("Failed to create account object")
            self.logger.debug(ae)
            self.logger.info("----- Terminating FMG -----")
            exit(1)

        # Prepare files and folders
        self.logger.debug("Preparing files and folders")
        try:
            self.acc.prepDir()
        except AccountError as ae:
            self.logger.critical("Failed to prepare account files and folders")
            self.logger.debug(ae)
            self.logger.debug("Calling account cleanup")
            self.acc.cleanup()
            self.logger.info("----- Terminating FMG -----")
            exit(1)

        # Unless forced execution, verify that all info is correct before beginning
        if not self.force:
            self.logger.debug("Prompting user for verification")
            print "------------------"
            print "VERIFY INFORMATION"
            print "------------------"
            print "Email: %s" % self.acc.email
            print "Username: %s" % self.acc.username
            print "Passord: %s" % self.acc.password
            print "Server: %s" % self.acc.serverurl
            print "Port: %s" % self.acc.port
            print "Protocol: %s" % self.acc.protocol
            if self.acc.ssl:
                print "SSL: Enabled"
            else:
                print "SSL: Disabled"
                print "------------------"
    
            yes = set(['yes', 'y', 'ja', 'j']) # Re-defining yes to avoid erronious verification
            while True:
                verify_info = raw_input("Is this information correct? [Yes/No]: ")
                if verify_info in yes:
                    self.logger.info("Information verified by user")
                    break
                elif verify_info in no:
                    self.logger.info("Information not verified by user")
                    self.logger.debug("Calling account cleanup")
                    self.acc.cleanup()
                    self.logger.info("----- Terminating FMG -----")
                    exit(1)
                else:
                    print "Invalid selection. Verification is mandatory. Try again!"
        else:
            self.logger.debug("Forced to continue without verification")

        # Go grab the email
        self.logger.info("Getting mail from %s", self.acc.email)
        self.logger.info("Username: %s", self.acc.username)
        self.logger.info("Password: %s", self.acc.password)
        self.logger.info("Server: %s",self.acc.serverurl)
        self.logger.info("Port: %s", self.acc.port)
        self.logger.info("Protocol: %s", self.acc.protocol)
        if not self.dry:
            if not self.quiet:
                print "Grabbing mail... "

                try:
                    self.acc.grabMail()
                    self.acc.retreived = False
                    self.acc.tried = True
                except Exception as e:
                    self.logger.error("Failed to grab mail")
                    self.logger.debug(e)
        else:
            self.logger.info("Dry run. No mail to process.")

        # Process the retreived mail
        if self.acc.retreived and self.acc.tried:
            self.logger.info("Processing retrived mail")
            if not self.dry:
                if not self.quiet:
                    print "Processing mail... "
                try:
                    self.acc.processMail()
                    if not self.quiet:
                        print "Mail processed"
                except AccountError as ae:
                    self.logger.warning("Failed to process retrieved mail")
        else:
            self.logger.info("Dry run. No mail to process.")

        # DO MORE STUFF HERE...

        # Clean up the account
        self.logger.debug("Cleaning up")
        self.acc.cleanup()

        self.logger.info("----- FMG Complete -----")
        return


### MAIN ###

# Parse command line arguments
ver  = "0.7 (2013-03-23 13:30 CET)"
byline = "by Stig Andersen <stig.andersen@politi.no>"
copyr = "(C) High Tech Crime Unit, Oslo Police District"
desc = """
Downloads and processes email from online email providers for forensic investigations.
Outputs to MBOX and Maildir. PDF and/or HTML output functionality to be added later.

USAGE NOTE:
If one or more command line options are missing, the script will prompt for input.
"""
epil = """
DISCLAIMER:
This script will attempt to access the email address to which you provide information.
Make sure you have legal access to the address before running this script!

This script is provided free of charge to law enforcement organizations world-wide.
This script may not be used in conjunction with any form of illegal activity.

No guarantee, warranty or insurance is provided.
USE AT YOUR OWN RISK!
"""

parser = argparse.ArgumentParser(description=desc, epilog=epil)

parser.add_argument('-e', '--email', help='The email address to grab', default=None)
parser.add_argument('-u', '--username', help='The username used to access the account', default=None)
parser.add_argument('-w', '--password', help='The password used to access the account', default=None)
parser.add_argument('-s', '--server', help='The server URL to access (e.g. imap.gmail.com)', default=None)
parser.add_argument('-p', '--port', help='The port on which to contact the server', default=None)

servertypegroup = parser.add_mutually_exclusive_group()
servertypegroup.add_argument('-I', '--imap', action='store_true', help='Communicate with the server using the IMAP protocol', default=False)
servertypegroup.add_argument('-M', '--mapi', action='store_true', help='Communicate with the server using the MAPI protocol', default=False)
servertypegroup.add_argument('-P', '--pop', action='store_true', help='Communicate with the server using the POP protocol', default=False)

sslgroup = parser.add_mutually_exclusive_group()
sslgroup.add_argument('-S', '--ssl', action="store_true", help='Communicate with the server using SSL encryption', default=False)
sslgroup.add_argument('-N', '--nossl', action="store_true", help="Communicate with the server without encryption", default=False)

verbosegroup = parser.add_mutually_exclusive_group()
verbosegroup.add_argument('-D', '--debug', action='store_true', help='Display debug information', default=False)
verbosegroup.add_argument('-V', '--verbose', action='store_true', help='Output more info to console during processing', default=False)
verbosegroup.add_argument('-Q', '--quiet', action='store_true', help='Output only necessary info to screen', default=False)

actiongroup = parser.add_mutually_exclusive_group()
actiongroup.add_argument('-d', '--dry', action='store_true', help='Dry-run. Do not access the server', default=False)
actiongroup.add_argument('-F', '--force', action='store_true', help='Ignore warnings and verifications. USE WITH CAUTION!', default=False)

args = parser.parse_args()

if not args.quiet:
    print "------------------------------------------------------"
    print "\tFMG - Forensic Mail Grabber"
    print "\t" + ver
    print "     " + byline
    print "   " + copyr
    print "------------------------------------------------------"

f = Fmg(email = args.email,
        username = args.username,
        password = args.password,
        server = args.server,
        port = args.port,
        imap = args.imap,
        mapi = args.mapi,
        pop = args.pop,
        ssl = args.ssl,
        nossl = args.nossl,
        debug = args.debug,
        verbose = args.verbose,
        quiet = args.quiet,
        dry = args.dry,
        force = args.force)
f.main()
