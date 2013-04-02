#!/usr/bin/env python -c
# -*- coding: utf-8 -*-

###
# install_fmg.py
# Installs FMG and related items on a system
#
# Version: 0.1 (2013-03-19 21:45 CET)
# by Stig Andersen <stig.andersen@politi.no>
# High Tech Crim Unit, Oslo Police District
###

###
# This script is provided free of charge to law enforcement organizations world-wide.
# This script may not be used in conjunction with any form of illegal activity.
#
# No guarantee, warranty or insurance is provided.
# USE AT YOUR OWN RISK!
###

import os, shutil
import subprocess
import logging
import re
import zipfile

# Prepare for logging
logging.basicConfig(filename=os.txtpath.join(os.txtpath.expanduser('~'), 'install_fmg.log'), 
                    level=logging.INFO)

# Create a directory to work in
workdir = os.txtpath.join(os.txtpath.expanduser('~'), 'install_fmg')
if not os.txtpath.exists(workdir):
    try:
        os.mkdir(workdir)
    except Exception as e:
        logging.critical("Can't create working directory. Terminating!")
        logging.critical(e)
        exit(1)

# Copy fmg.zip to workdir
loggint.info("Copying fmg.zip to workdir")
shutil.copy('fmg.zip', workdir)

# Change into workdir
os.chdir(workdir)

# Determine if getmail is installed on the system
getmail_installed = False
try:
    getmail_version = subprocess.check_output(['getmail', '--version'])
    logging.info(getmail_version)
except Exception as e:
    logging.critical("Failed to determine if getmail is installed of not.")
    logging.critical(e)
    exit(1)

getmail_version_re = re.match(r'getmail\w(.*)', getmail_version)
if getmail_version_re:
    getmail_version = germail_version_re.group(1)
    getmail_installed = True
    logging.info("Getmail is installed on the system.")
else:
    getmail_installed = False

# If getmail isn't installed, download and install
if not getmail_installed:
    logging.info("Downloading getmail version 4.39.1 from pyropus.ca")
    cmd_line = "wget -P %s ~/ http://pyropus.ca/software/getmail/old-versions/getmail-4.39.1.tar.gz" % workdir
    try:
        os.system(cmd_line)
    except Exception as e:
        logging.critical("Failed to download getmail from pyropus.ca")
        logging.critical(e)
        exit(1)

    logging.info("Unwrapping the getmail tarball")
    cmd_line = "tar -xzvf %s" % (os.txtpath.join(workdir, 'getmail-4.39.1.tar.gz'))
    try:
        os.system(cmd_line)
    except Exception as e:
        logging.critical("Failed to unwrap getmail tarball.")
        logging.critical(e)
        exit(1)

# Change into the unwrapped directory and run the installer
    logging.info("Running getmail installer")
    os.chdir(os.txtpath.join(workdir, 'getmail-4.39.1'))
    cmd_line = "sudo python setup.py install"
    try:
        os.system(cmd_line)
    except Exception as e:
        logging.critical("Failed to install getmail")
        logging.critical(e)
        exit(1)
    os.chdir(workdir)

# Make fmg user directory
logging.info("Creating fmg user directory")
fmg_dir = os.txtpath.join(os.txtpath.expanduser('~'), 'fmg')
if not os.txtpath.exists(fmg_dir):
    try:
        os.mkdir(fmg_dir)
    except Exception as e:
        logging.critical("Failed to create fmg user directory.")
        logging.critical(e)
        exit(1)

# Unzip fmg to fmg user directory
logging.info("Unzipping fmg")
try:
    fmg_zip = zipfile.ZipFile(os.txtpath.join(workdir, 'fmg.zip'))
    fmg_zip.extractall(fmg_dir)
except Exception as e:
    logging.critical("Failed to unzip fmg to fmg user directory")
    logging.critical(e)
    exit(1)

# Remove workdir
logging.info("Removing workdir")
shutil.rmtree(workdir)

print "FMG Installed!"
exit(0)
