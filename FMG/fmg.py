#!/usr/bin/env python -c
# -*- coding: utf-8 -*-

###
# fmg.py
# Forensic Mail Grabber
# by Stig Andersen <stig.andersen@politi.no>
# Digital Forensics Unit, Oslo Police District
###

# IMPORT SYSTEM PACKAGES #
import logging  # @UnresolvedImport
import os.path
import shutil
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
    pop = None # For future implementation
    mapi = None # For future implementation

    ssl = None
    nossl = None
    
    targetdir = None

    debug = None
    verbose = None
    quiet = None

    dry = None
    force = None

    acc = None
    
    masterlog_path = None
    masterlog_filename = None
    runlog_path = None
    runlog_filename = None
    debuglog_path = None
    debuglog_filename = None

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
        self.masterlog_path = os.path.join(os.path.expanduser("~"), "fmg")
        self.masterlog_filename = "fmg.log"
        masterlog = logging.FileHandler(os.path.join(self.masterlog_path, self.masterlog_filename))
        masterlog.setLevel(logging.INFO)
        masterlog.setFormatter(fileformatter)
        self.logger.addHandler(masterlog)

        # Runlog
        self.runlog_path = self.masterlog_path
        self.runlog_filename = "fmg_%s.log" % (strftime("%Y-%m-%d-%H%M%S_%Z", localtime()))
        runlog = logging.FileHandler(os.path.join(self.runlog_path, self.runlog_filename), mode='w')
        runlog.setLevel(logging.INFO)
        runlog.setFormatter(fileformatter)
        self.logger.addHandler(runlog)

        # Debuglog
        if self.debug:
            self.debuglog_path = self.masterlog_path
            self.debuglog_filename = "fmg_debug.log"
            debuglog = logging.FileHandler(os.path.join(self.debuglog_path, self.debuglog_filename))
            debuglog.setLevel(logging.DEBUG)
            self.logger.addHandler(debuglog)

        return

    # Get email address input
    def getInput_email(self):
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
        return

    # Validate and set username
    def getInput_username(self):
        self.logger.debug("Setting username")
        if self.username:
            self.logger.debug("Using username from cmd.line argument")
        elif not self.force:
            self.logger.debug("Prompting for username verification")
            email_re = re.match(r"(.+)@(.+)", self.email)
            input_txt = "Use '%s' as username? [YES/No/Cancel]: " % email_re.group(1)
            verify_username = None
            while True:
                verify_username = raw_input(input_txt).lower()
                if verify_username in yes:
                    self.logger.debug("Username verified by user")
                    self.username = email_re.group(1)
                    break
                elif verify_username in no:
                    self.logger.debug("Username not correct according to user")
                    break
                elif verify_username in cancel:
                    self.logger.info("Username verification cancelled")
                    self.logger.info("----- Terminating FMG -----")
                    exit(1)
                else:
                    print "Invalid selection, try again!"

            # Get username from user
            if verify_username in no:
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

        else:
            self.logger.info("Assuming username from email address")
            email_re = re.match(r"(.+)@(.+)", self.email)
            self.username = email_re.group(1)
            if self.username == "":
                self.logger.critical("Forced to terminate: No username!")
                self.logger.info("----- Terminating FMG -----")
                exit(1)
        return

    # Validate and set password (NOTE: Password is not validated against the server. Only input validation.)
    def getInput_password(self):
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
        return

    # Validate and set server URL
    def getInput_serverurl(self):
        self.logger.debug("Setting server url")
        if self.serverurl:
            self.logger.debug("Using server URL from cmd.line argument")
        elif not self.force:
            self.logger.debug("Prompting for server URL")
            verify_url = False
            
            self.logger.debug("Getting server url from email address")
            email_re = re.match(r"(.+)@(.+)", self.email)
            
            # IMAP is the only protocol currently supported by FMG
            self.imap = True

            if self.imap or self.pop:
                if self.imap:
                    self.logger.debug("Protocol is IMAP, completing server url accordingly")
                    self.serverurl = "imap." + email_re.group(2)
                elif self.pop:
                    self.logger.debug("Protocol is POP, completing server url accordingly")
                    self.serverurl = "pop." + email_re.group(2)
                else:
                    self.logger.debug("No protocol identified. Using 'mail' as subdomain.")
                    self.serverurl = "mail." + email_re.group(2)

            input_txt = "Use %s as server url? [YES/No/Cancel]: " % self.serverurl

            while True:
                verify_url = raw_input(input_txt).lower()
                if verify_url in yes:
                    self.logger.debug("Server url verified by user")
                    verify_url = True
                    break
                elif verify_url in no:
                    verify_url = False
                    break
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
                        self.logger.debug("Server url entered: '%s'", self.serverurl)
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
        return

    # Validate and set protocol
    def getInput_protocol(self):
        self.logger.debug("Setting protocol")
        
        # Try to get protocol selection from server url
        if self.imap:
            self.logger.debug("Protocol 'IMAP' set as cmd.line argument")
            self.protocol = 'IMAP'
        elif self.pop:
            self.logger.debug("Protocol 'POP' set as cmd.line argument")
            self.protocol = 'POP'
        elif "imap" in self.serverurl.lower():
            self.logger.debug("Found 'imap' in server url.")
            verify_protocol = raw_input("Use IMAP protocol? [YES/No/Cancel]: ").lower()
            if verify_protocol in yes:
                self.logger.debug("Setting protocol to 'IMAP'")
                self.protocol = 'IMAP'
            if verify_protocol in no:
                self.logger.debug("Protocol selection cleared.")
                self.protocol = None
            if verify_protocol in cancel:
                self.logger.info("Protocol selection cancelled.")
                self.logger.info("----- Terminating FMG -----")
                exit(1)
                
        # POP isn´t implemented!
        elif "pop" in self.serverurl.lower():
            self.logger.debug("Found 'pop' in server url. Setting protocol to 'POP'")
            verify_protocol = raw_input("Use POP protocol? [YES/No/Cancel]: ").lower()
            if verify_protocol in yes:
                self.logger.debug("Setting protocol to 'POP'")
                self.protocol = 'POP'
            if verify_protocol in no:
                self.logger.debug("Protocol selection cleared.")
                self.protocol = None
            if verify_protocol in cancel:
                self.logger.info("Protocol selection cancelled.")
                self.logger.info("----- Terminating FMG -----")
                exit(1)
        # Prompt user for protocol selection, unless force.
        if not self.force and not self.protocol:
            self.logger.debug("Prompting for protocol selection")
            imap = set(['imap', 'i', ''])
            pop = set(['pop', 'p']) # For future implementation
            while True:
                select_protocol = raw_input("Select server protocol type [IMAP, Pop] (Type 'c' to cancel'): ").lower()
                if select_protocol in imap:
                    self.logger.debug("Setting protocol to 'IMAP'")
                    self.protocol = 'IMAP'
                    break
                # POP isn´t implemented!
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
            if "pop" in self.serverurl.lower():
                self.logger.info("Found POP in server url, using protocol POP.")
                self.protocol = 'POP'
            else:
                self.logger.info("Assuming default protocol IMAP.")
                self.protocol = 'IMAP'
        return

    # Validate and set SSL
    def getInput_ssl(self):
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
                verify_ssl = raw_input("Use SSL encryption? [YES/No/Cancel]: ").lower()
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
        return

    # Validate and set server port
    def getInput_port(self):
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
                self.port = "143"
            elif self.protocol == 'POP' and self.ssl:
                self.logger.debug("Protocol is POP and SSL is set. Suggesting default secure POP3 (SSL-POP) port")
                self.port = "995"
            elif self.protocol == 'POP' and not self.ssl:
                self.logger.debug("Protocol is POP and SSL is NOT set. Suggesting default POP3 port")
                self.port = "110"

            input_txt = "Use %s as server port? [YES/No/Cancel]: " % self.port
            while True:
                verify_port = raw_input(input_txt).lower()
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
        
	# Validate and set target directory
    def getInput_targetdir(self):
        self.logger.debug("Setting target directory")
        if self.targetdir:
            self.logger.debug("Target directory set from cmd.line argument")
        elif not self.force:
            self.logger.debug("Prompting for target directory")
            while True:
                self.targetdir = raw_input("Target directory (Hit 'enter' to default, type 'c' to cancel): ")
                self.logger.debug("Target directory entered: %s", self.targetdir)
                if self.targetdir == "":
                    self.logger.debug("Using default target directory")
                    self.targetdir = os.path.join(os.path.expanduser("~"), "fmg")
                    break
                elif os.path.isabs(self.targetdir):
                    self.logger.debug("Validated target directory")
                    break
                elif self.targetdir in cancel:
                    self.logger.info("Target directory input cancelled")
                    self.logger.info("----- Terminating FMG -----")
                    exit(1)
                else:
                    print "Not a valid directory. Try again!"
        else:
            self.logger.debug("Forced to assume default target directory")
            self.targetdir = os.path.join(os.path.expanduser("~"), "fmg")
        return

    # GET AND VALIDATE INPUT #
    def getInput(self):
        """VALIDATE INPUT, SET CORRECT VALUES, PROMPT FOR MISSING VALUES"""
        self.getInput_email()
        self.getInput_username()
        self.getInput_password()
        self.getInput_serverurl()
        self.getInput_protocol()
        self.getInput_ssl()
        self.getInput_port()
        self.getInput_targetdir()
        return

    # FMG INIT #
    def __init__(self, email, username, password, serverurl, port, imap, mapi, pop, ssl, 
                 nossl, targetdir, debug, verbose, quiet, dry, force):
        # Prepare variables
        self.email = email
        self.username = username
        self.password = password
        self.serverurl = serverurl
        self.port = port
        self.imap = imap
        self.mapi = mapi # Leaving MAPI in for future implementation
        self.pop = pop # For future implementation
        self.ssl = ssl
        self.nossl = nossl
        self.targetdir = targetdir
        self.debug = debug
        self.verbose = verbose
        self.quiet = quiet
        self.dry = dry
        self.force = force

		# Prepare the logs
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
                               self.ssl,
                               self.targetdir)
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
            print "Target directory: %s" % self.acc.targetdir
            print "------------------"
    
            yes = set(['yes', 'y', 'ja', 'j']) # Re-defining yes to avoid false verification
            while True:
                verify_info = raw_input("Is this information correct? [Yes/No]: ").lower()
                if verify_info in yes:
                    self.logger.info("Information verified by user")
                    break
                elif verify_info in no:
                    self.logger.info("Information not verified by user")
                    self.logger.info("----- Terminating FMG -----")
                    exit(1)
                else:
                    print "Invalid selection. Verification is mandatory. Try again!"
        else:
            self.logger.debug("Forced to continue without verification")

        # Go grab the email
        self.logger.info("Getting mail from %s", self.acc.email)
        self.logger.info("User name: %s", self.acc.username)
        self.logger.info("Password: [NOT LOGGED]")#%s", self.acc.password)
        self.logger.info("Server: %s",self.acc.serverurl)
        self.logger.info("Port: %s", self.acc.port)
        self.logger.info("Protocol: %s", self.acc.protocol)
        if not self.dry:
            if not self.quiet:
                print "Grabbing mail... "
            try:
                self.acc.grabMail()
                print "Grabbing complete."
            except Exception as e:
                self.logger.error("Failed to grab mail")
                self.logger.debug(e)
        else:
            self.logger.info("Dry run. No mail to process.")

        # Post-process the retrieved mail
        if self.acc.retrieved:
            self.logger.info("Post-Processing")
            if not self.dry:
                if not self.quiet:
                    print "Post-Processing mail... "
                try:
                    self.acc.postprocess()
                    if not self.quiet:
                        print "Post-Processing complete"
                except AccountError as ae:
                    self.logger.warning("Failed to post-process retrieved mail")

            else:
                self.logger.info("Dry run. No post-processing necessary.")
        else:
            self.logger.warn("No mail retrieved, no post-processing necessary.")
            
        # Copy the runlog to the target directory
        if self.targetdir != self.runlog_path:
            self.logger.debug("Copying runlog to target directory")
            shutil.copy2(os.path.join(self.runlog_path, self.runlog_filename),
                         os.path.join(self.targetdir, self.runlog_filename))

        # Terminate
        self.logger.info("----- FMG Complete -----")
        return


### MAIN ###

# Parse command line arguments
ver  = "0.3 BETA (2013-12-20)"
byline = "by Stig Andersen <stig.andersen@politi.no>"
copyr = "(C) Digital Forensics Unit, Oslo Police District"
desc = """
Downloads and processes email from online email providers for digital forensic investigations.
Outputs to MBOX and plain text, and stores attachments. All files are hashed using SHA-1.

USAGE NOTE:
If one or more command line options are missing, the script will prompt for input.
"""
epil = """
DISCLAIMER:
Forensic Mail Grabber consists of several files. Any reference in the following to "FMG", "Forensic Mail Grabber",
"this script" or similar shall be understood to include all files related to the Forensic Mail Grabber project.

FMG will attempt to access the email account and related server to which you provide information. Make sure you have
legal access to the address before running this script!

FMG is provided free of charge to domestic law enforcement organizations world-wide. FMG script may not be used for
any form of illegal activity, including espionage and foreign intelligence collection.

FMG is provided as-is. The authors, the Norwegian government, its instrumentalities, officers, employees and other
collaborators to the FMG project, make NO WARRANTY, express or implied, as to the usefullness of the script and documentation
for any purpose. They assume no responsibility for the use of the script and documentation, or to provide technical support.

USE AT YOUR OWN RISK!
"""

parser = argparse.ArgumentParser(description=desc, epilog=epil)

parser.add_argument('-e', '--email', help='The email address to grab', default=None)
parser.add_argument('-u', '--username', help='The username used to access the account', default=None)
parser.add_argument('-w', '--password', help='The password used to access the account', default=None)
parser.add_argument('-s', '--server', help='The server URL to access (e.g. imap.gmail.com)', default=None)
parser.add_argument('-p', '--port', help='The port on which to contact the server', default=None)
parser.add_argument('-t', '--targetdir', help='Target directory in which to store the result. (Defaults to the FMG directory)', default=None)

servertypegroup = parser.add_mutually_exclusive_group()
servertypegroup.add_argument('-I', '--imap', action='store_true', help='Communicate with the server using the IMAP protocol', default=False)
# MAPI and POP options removed - functionality not implemented.
# servertypegroup.add_argument('-M', '--mapi', action='store_true', help='Communicate with the server using the MAPI protocol', default=False)
# servertypegroup.add_argument('-P', '--pop', action='store_true', help='Communicate with the server using the POP protocol', default=False)

sslgroup = parser.add_mutually_exclusive_group()
sslgroup.add_argument('-S', '--ssl', action="store_true", help='Communicate with the server using SSL encryption', default=False)
sslgroup.add_argument('-N', '--nossl', action="store_true", help="Communicate with the server without encryption", default=False)

verbosegroup = parser.add_mutually_exclusive_group()
verbosegroup.add_argument('-D', '--debug', action='store_true', help='Display debug information', default=False)
verbosegroup.add_argument('-V', '--verbose', action='store_true', help='Display more info to console during processing', default=False)
verbosegroup.add_argument('-Q', '--quiet', action='store_true', help='Display only necessary info to screen', default=False)

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
        serverurl = args.server,
        port = args.port,
        imap = args.imap,
        mapi = None, #args.mapi, # MAPI isn´t implemented!
        pop = None, #args.pop, # POP isn´t implemented!
        ssl = args.ssl,
        nossl = args.nossl,
        targetdir = args.targetdir,
        debug = args.debug,
        verbose = args.verbose,
        quiet = args.quiet,
        dry = args.dry,
        force = args.force)
f.main()
