#!/usr/bin/env python3
#
# UpdateDenySenders.py -- Add Sender email addresses/domain and TLD patterns to list file
# Copyright (c) 2026 Lucía Andrea Illanes Albornoz <lucia@luciaillanes.de>
# This project is licensed under the terms of the MIT licence.
#
# Use in conjunction with
# a) a MUA that can be configured to display the email envelope Sender header at all times or
#    when it differs from the From address
# b) an IMAP server such as Dovecot that can be configured to invoke this script on moving a
#    spam email into the corresponding virtual email folder
# c) an MTA that can be configured to deny email envelope senders after RCPT TO from any of:
#    1) a list of single email addresses or patterns thereof in $HOME/.deny_senders
#    2) a list of email address domain parts or patterns thereof in $HOME/.deny_senders.domains
#
# [[[ Example Dovecot configuration
# /etc/dovecot/sieve/deny-address.sieve:
# require ["vnd.dovecot.pipe", "copy", "imapsieve", "environment", "variables"];
#
# if environment :matches "imap.user" "*" {
#   set "username" "${1}";
# }
#
# pipe :copy "deny-address.sh" [ "${username}" ];
# discard;
#
# /etc/dovecot/sieve/deny-address.sh:
# #!/bin/sh
# export USER="${1}"; shift;
# export HOME="${HOME:-$(getent passwd "${USER}" | awk -F: '{print $6}')}";
# exec "${HOME}/.local/bin/UpdateDenySenders.py" -a -l -r "${@}";
#
# /etc/dovecot/sieve/deny-domain.sieve:
# require ["vnd.dovecot.pipe", "copy", "imapsieve", "environment", "variables"];
#
# if environment :matches "imap.user" "*" {
#   set "username" "${1}";
# }
#
# pipe :copy "deny-domain.sh" [ "${username}" ];
# discard;
#
# /etc/dovecot/sieve/deny-domain.sh:
# #!/bin/sh
# export USER="${1}"; shift;
# export HOME="${HOME:-$(getent passwd "${USER}" | awk -F: '{print $6}')}";
# exec "${HOME}/.local/bin/UpdateDenySenders.py" -d -l -r "${@}";
# ]]]
# [[[ Example Exim MTA configuration
# warn
#   condition = ${if and{\
#     {!eq{$sender_address}{}}\
#   }{true}{false}}
#   remove_header = Sender:
#   add_header = Sender: $sender_address
#
# [...]
#
# deny_senders:
#   driver = redirect
#   domains = +local_domains
#   check_local_user
#   allow_fail
#   condition = ${if exists{${expand:${home}/.deny_senders}}{${lookup{$sender_address}nwildlsearch{${expand:${home}/.deny_senders}}{1}{0}}}{0}}
#   data = :fail: Access denied: sender address $sender_address is not allowed
#
# deny_senders_domains:
#   driver = redirect
#   domains = +local_domains
#   check_local_user
#   allow_fail
#   condition = ${if exists{${expand:${home}/.deny_senders.domains}}{${lookup{$sender_address_domain}nwildlsearch{${expand:${home}/.deny_senders.domains}}{1}{0}}}{0}}
#   data = :fail: Access denied: sender address $sender_address is not allowed
# ]]]
#

from getopt import getopt

import os
import re
import shutil
import smtplib
import socket
import sys
import tldextract

class DenySendersList(object):
    """Add Sender email addresses/domain and TLD patterns to list file"""

    # [[[ def getEmailAddress(self, buffer)
    def getEmailAddress(self, buffer):
        matches = re.search(self.emailSenderRegex, buffer)
        if matches is None:
            self.printWarnErr("warning: Sender header not found in email on stdin, ignoring.")
            return False, None
        else:
            address = matches.group(1)
            if "@" not in address:
                self.printWarnErr("warning: invalid Sender header email address {} in email on stdin, ignoring.".format(address))
                return False, None
            else:
                return True, address
    # ]]]
    # [[[ def getEmailDomainTld(self, address)
    def getEmailDomainTld(self, address):
        address = address.split("@")[-1:][0]
        address = ".".join([L for L in address.split(".") if len(L) > 0])
        tldExtractResult = tldextract.extract(address)

        if len(tldExtractResult.suffix) == 0:
            self.printWarnErr("warning: missing TLD in Sender header email address part {}, ignoring.".format(address))
            return False, None
        else:
            addressDomainTld = tldExtractResult.domain + "." + tldExtractResult.suffix
            return True, addressDomainTld
    # ]]]
    # [[[ def writeLine(self, file, lineNew)
    def writeLine(self, file, lineNew):
        lines = file.read().split("\n")
        lines = [L for L in lines if len(L) > 0]

        if lineNew.upper() in map(str.upper, lines):
            self.printWarnErr("warning: duplicate entry {} in {}, ignoring.".format(lineNew, self.listFname))
        else:
            if self.logFile is not None:
                print("Adding {} to {}".format(lineNew, self.listFname), file=self.logFile)
            if "r" in self.options:
                self.printReportLine("Adding {} to {}".format(lineNew, self.listFname))
            if "v" in self.options:
                print("Adding {} to {}".format(lineNew, self.listFname), file=sys.stderr)

            lines += [lineNew]; lines.sort()
            file.seek(0)
            file.write("\n".join(lines) + "\n")
            file.truncate()
    # ]]]

    # [[[ def getOptions(self)
    def getOptions(self):
        options = {}
        optionsList, args = getopt(self.argv[1:], "adf:hlL:rv")
        for optionChar, optionArg in optionsList:
            options[optionChar[1:]] = optionArg

        if "h" in options:
            self.printUsage()
            return False, 0, None
        elif (("a" not in options) and ("d" not in options))\
        or   ((    "a" in options) and (    "d" in options)):
            self.printUsage("error: either of -a or -d must be specified")
            return False, 1, None
        else:
            homeDname = os.environ["HOME"].rstrip("/")
            if "f" not in options:
                if "a" in options:
                    options["f"] = homeDname + "/" + ".deny_senders"
                elif "d" in options:
                    options["f"] = homeDname + "/" + ".deny_senders.domains"
            elif not options["f"][0] == "/":
                options["f"] = homeDname + "/" + options["f"]

            self.options = options
            return True, 0, args
    # ]]]
    # [[[ def initOptions(self, args)
    def initOptions(self, args):
        self.listFname = self.options["f"]
        self.emailSenderRegex = re.compile('^Sender: (.*)$', re.IGNORECASE | re.MULTILINE)

        if "l" in self.options:
            if "L" in self.options:
                logFname = self.options["L"]
            else:
                logFname = self.options["f"] + ".log"

            try:
                self.logFile = open(logFname, "a")
            except Exception as e:
                print("error: {} when opening log file {}, exiting.".format(e, logFname), file=sys.stderr)
                return False, 1
        else:
            self.logFile = None

        if "r" in self.options:
            self.localUser = (os.environ["USER"] if ("USER" in os.environ) else "unknown_user")
            self.localHost = socket.gethostname()
            self.reportLines = []

            self.printReportLine("From: {}".format(self.localUser))
            self.printReportLine("To: {}".format(self.localUser))
            self.printReportLine("Subject: Deny senders file update report for {}@{}".format(self.localUser, self.localHost))
            self.printReportLine("")

        return True, 0
    # ]]]
    # [[[ def printUsage(self, *args)
    def printUsage(self, *args):
        for message in args:
            print(message, file=sys.stderr)
        print("""\
usage: {}
       [-a] [-d] [-f fname] [-h] [-l] [-L fname] [-r] [-v]

-a.........: selects deny single email address mode
-d.........: selects deny email address domain and TLD pattern mode
-f fname...: manually specify deny list pathname (defaults to $HOME/.deny_senders or $HOME/.deny_senders.domains)
-h.........: print this screen and exit
-l.........: log deny list updates (see -L)
-L fname...: set deny list updates log file to <fname> (defaults to $HOME/.deny_senders.log or $HOME/.deny_senders.domains.log)
-r.........: print injectable email report to stdout on exit
-v.........: log deny list additions to stderr

A single email is read from stdin.
A copy of the deny list file is saved with the file extension ".bak" on each run."""
            .format(self.argv[0]), file=sys.stderr)
    # ]]]
    # [[[ def printWarnErr(self, *args, **kwargs)
    def printWarnErr(self, *args, **kwargs):
        if "r" in self.options:
            self.printReportLine(*args, **kwargs)
        print(*args, **kwargs, file=sys.stderr)
    # ]]]

    # [[[ def printReportLine(self, line):
    def printReportLine(self, line):
        self.reportLines += [line]
    # ]]]
    # [[[ def sendReport(self)
    def sendReport(self):
        smtpSession = smtplib.SMTP("localhost")
        try:
            smtpSession.sendmail(
                self.localUser + "@" + self.localHost,
                self.localUser + "@" + self.localHost,
                "\n".join(self.reportLines) + "\n")
        except Exception as e:
            self.printWarnErr("error: {} when sending report email from {} to {}."
                              .format(e, self.localUser, self.localUser))
            return False
        else:
            return True
    # ]]]

    def synchronise(self):
        status, rc, args = self.getOptions()
        if not status:
            return rc
        else:
            status, rc = self.initOptions(args)
            if not status:
                return rc

        if os.path.exists(self.listFname):
            shutil.copy2(self.listFname, self.listFname + ".bak")
        emailBuffer = sys.stdin.read()
        status, emailAddress = self.getEmailAddress(emailBuffer)
        if status and ("d" in self.options):
            status, emailAddress = self.getEmailDomainTld(emailAddress)
        if status:
            try:
                listFile = open(self.listFname, "a+")
            except Exception as e:
                self.printWarnErr("error: {} when opening deny senders file {}, ignoring.".format(e, self.listFname))
                rc = 1
            if rc == 0:
                with listFile:
                    if "a" in self.options:
                        lineNew = emailAddress
                    elif "d" in self.options:
                        lineNew = '^(.*\\.)?{}$'.format(re.escape(emailAddress))
                    self.writeLine(listFile, lineNew)

        if self.logFile is not None:
            self.logFile.close()

        if "r" in self.options:
            if not self.sendReport():
                rc = 1

        return rc

    def __init__(self, argv):
        self.argv = argv

if __name__ == "__main__":
    exit(DenySendersList(sys.argv).synchronise())

# vim:expandtab foldmarker=[[[,]]] foldmethod=marker sw=4 ts=4 tw=120
