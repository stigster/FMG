FMG
===

Forensic Mail Grabber

Fetches email from email servers and stores them in a variety of formats handy for digital forensic investigations.
Downloaded email, as well as produced output, is hashed for validity and notoriety, and ZIPed for easy storage and
transfer. All actions are logged.

By Stig Andersen,
stig dot andersen at politiet dot no,
Digital Forensic Unit,
Oslo Police District,
Norway

### DISCLAIMER:

Forensic Mail Grabber consists of several files. Any reference in the following to "FMG", "Forensic Mail Grabber",
"this script" or similar shall be understood to include all files related to the Forensic Mail Grabber project.

FMG will attempt to access the email account and related server to which you provide information.
Make sure you have legal access to the address before running this script!

FMG is provided free of charge to domestic law enforcement organizations world-wide.
FMG script may not be used for any form of illegal activity, including espionage and foreign intelligence collection.

FMG is provided as-is. The authors, the Norwegian government, its instrumentalities, officers, employees and other
collaborators to the FMG project, make NO WARRANTY, express or implied, as to the usefullness of the script and
documentation for any purpose. They assume no responsibility for the use of the script and documentation, or to
provide technical support.

**USE AT YOUR OWN RISK!**

### USAGE:
Invoke FMG with a python interpreter. If a required argument is missing, the script will prompt for input - except if
the FORCE option is engaged.

```
$ fmg.py [-h] [-e EMAIL] [-u USERNAME] [-w PASSWORD] [-s SERVER]
              [-p PORT] [-I | -M | -P] [-S | -N] [-D | -V | -Q] [-d | -F]

optional arguments:
  -h, --help            show this help message and exit
  -e EMAIL, --email EMAIL
                        The email address to grab
  -u USERNAME, --username USERNAME
                        The username used to access the account
  -w PASSWORD, --password PASSWORD
                        The password used to access the account
  -s SERVER, --server SERVER
                        The server URL to access (e.g. imap.gmail.com)
  -p PORT, --port PORT  The port on which to contact the server
  -I, --imap            Communicate with the server using the IMAP protocol
  -M, --mapi            Communicate with the server using the MAPI protocol
  -P, --pop             Communicate with the server using the POP protocol
  -S, --ssl             Communicate with the server using SSL encryption
  -N, --nossl           Communicate with the server without encryption
  -D, --debug           Display debug information
  -V, --verbose         Output more info to console during processing
  -Q, --quiet           Output only necessary info to screen
  -d, --dry             Dry-run. Do not access the server
  -F, --force           Ignore warnings and verifications. USE WITH CAUTION!
```

### EXAMPLE RUN:
Running FMG without options (`$ python fmg.py`) will look something like this. In this run, default
values have been selected where applicable.
```
------------------------------------------------------
        FMG - Forensic Mail Grabber
        0.2 BETA (2013-04-04)
     by Stig Andersen <stig.andersen@politi.no>
   (C) High Tech Crime Unit, Oslo Police District
------------------------------------------------------
Email address (Type 'c' to cancel): username@email.com
Use 'username' as username? [YES/No/Cancel]:
Password: MyPassword
Server URL: imap.email.com
Use IMAP protocol? [YES/No/Cancel]:
Use SSL encryption? [YES/No/Cancel]:
Use 993 as server port? [YES/No/Cancel]:
------------------
VERIFY INFORMATION
------------------
Email: username@email.com
Username: username
Passord: MyPassword
Server: imap.email.com
Port: 993
Protocol: IMAP
SSL: Enabled
Is this information correct? [Yes/No]: yes
Grabbing mail...
Grabbing complete.
Post-processing mail...
Post-Processing complete.
```
