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
    local_path = None # The local path to where content from this mailbox is stored
    remote_item = None # The remote mailbox item
    
    def __init__(self, name, local_path, remote_path):
        self.name = name
        self.local_path = local_path
        self.remote_path = remote_path
        return
    
    def __str__(self):
        return self.name
    