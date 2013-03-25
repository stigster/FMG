#!/usr/bin/env python -c
# -*- coding: utf-8 -*-

###
# accountError.py - Defines exceptions and errors for account class
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

class AccountError(Exception):
    """General purpose Account class exception"""

    def __init__(self, msg):
        self.msg = msg
        return

    def __str__(self):
        return repr(self.msg)
