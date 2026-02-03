#!/usr/bin/env python3
#
# DiscogsUpdates.py -- Discogs Marketplace change notification script (for pagga)
# Copyright (c) 2019 Lucía Andrea Illanes Albornoz <lucia@luciaillanes.de>
# This project is licensed under the terms of the MIT licence.
#

from email.message import EmailMessage
from getopt import getopt
import daemon, json, logging, os, requests, subprocess, sys, time

class DiscogsUpdatesFormatter(logging.Formatter):
    # {{{
    FORMATS = {"DEFAULT": "%(msg)s"}

    def format(self, record):
        loggingFormat = self.FORMATS.get(record.levelno, self.FORMATS["DEFAULT"])
        return logging.Formatter(loggingFormat).format(record)
    def formatTime(self, record, datefmt=None):
        return time.strftime(datefmt if datefmt is not None else "%d-%^b-%Y %H:%M:%S")
    def __init__(self, toTerminal):
        if toTerminal:
            self.FORMATS[logging.DEBUG] = "\x1b[33m%(asctime)s\x1b[0m \x1b[36m%(msg)s\x1b[0m"
            self.FORMATS[logging.ERROR] = "\x1b[33m%(asctime)s\x1b[0m \x1b[91m%(msg)s\x1b[0m"
            self.FORMATS[logging.INFO] = "\x1b[33m%(asctime)s\x1b[0m \x1b[93m%(msg)s\x1b[0m"
        else:
            self.FORMATS[logging.DEBUG] = "%(asctime)s %(msg)s"
            self.FORMATS[logging.ERROR] = "%(asctime)s %(msg)s"
            self.FORMATS[logging.INFO] = "%(asctime)s %(msg)s"
    # }}}

class DiscogsUpdates(object):
    """Discogs Marketplace change notification class"""
    # {{{ Class attributes
    apiUrlBase = "https://api.discogs.com"
    discogsDbPath = os.path.expanduser(os.path.join("~", ".cache", "DiscogsUpdates.db"))
    helpString = """usage: {argv0} [-d] [-h] [-i interval] [-m from:to] [-v] [--] [release[..]]
       -d...........: daemonise into the background (defaults to: {self.optionsDefault[daemonise]})
       -h...........: show this screen
       -i interval..: polling interval in seconds (defaults to: {self.optionsDefault[interval]})
       -m from:to...: send change notifications per email from {{from,to}} addresses (defaults to: {self.optionsDefault[mail]})
       -v...........: increase verbosity (defaults to: {self.optionsDefault[verbose]})
       -w username..: obtain list of releases from username's want list (defaults to: {self.optionsDefault[wantListUser]}"""
    optionsDefault = {"daemonise":False, "help":False, "interval":(10 * 60), "mail":None, "verbose":False, "wantListUser":None}
    optionsString = "dhi:m:vw:"
    optionsStringMap = {"d":"daemonise", "h":"help", "i":"interval", "m":"mail", "v":"verbose", "w":"wantListUser"}
    userAgent = "DiscogsUpdates/1.0 +https://github.com/lalbornoz"
    # }}}
    # {{{ _dataFetch(self, apiUrlBase, release):
    def _dataFetch(self, apiUrlBase, release):
        while True:
            apiUrl = "{}/releases/{}".format(apiUrlBase, release)
            self.logger.debug("Fetching [4m{apiUrl}[0m...".format(**locals()))
            response = requests.get(apiUrl, headers={"User-Agent":self.userAgent})
            responseStatus = response.status_code
            if responseStatus == 200:
                return response.json()
            elif responseStatus == 429:
                self.logger.error("rate limit of 60 requests per minute exceeded, waiting 60 seconds (message: `{}')".format(response.json()["message"]))
                time.sleep(60)
            else:
                self.logger.error("non-successful status received, message: `{}'".format(response.json()["message"]))
                return None
    # }}}
    # {{{ _dataMerge(self, changeFlag, data, discogsDb, release)
    def _dataMerge(self, changeFlag, data, discogsDb, release):
        self.logger.debug("release #{}, lowest price: {}, num. for sale: {}".format(release, data["lowest_price"], data["num_for_sale"]))
        if  release in discogsDb                                        \
        and discogsDb[release]["lowest_price"] == data["lowest_price"]  \
        and discogsDb[release]["num_for_sale"] == data["num_for_sale"]:
            return changeFlag, discogsDb, True
        else:
            changeFlag, discogsDb[release] = True, {"lowest_price":data["lowest_price"], "num_for_sale":data["num_for_sale"]}
            self.logger.info("new release #{} change notification, current lowest price: {}, current num. for sale: {}".format(release, data["lowest_price"], data["num_for_sale"]))
            return True, discogsDb, True
    # }}}
    # {{{ _dataChangeNotify(self, changeFlag, data, discogsDb, releases)
    def _dataChangeNotify(self, changeFlag, data, discogsDb, releases):
        if changeFlag and self.options["mail"] is not None:
            content = ""
            for release in releases:
                dbValue, message = discogsDb[release], EmailMessage()
                content += "Release #{release}: current lowest price: {dbValue[lowest_price]}, current num. for sale: {dbValue[num_for_sale]}\n".format(**locals())
            message.set_content(content)
            message["From"] = self.options["mail"]["from"]
            message["Subject"] = "Discogs release(s) {} change notification".format(", ".join(["#" + release for release in releases]))
            message["To"] = self.options["mail"]["to"]
            try:
                self.logger.debug("sending change notification email from {self.options[mail][from]} to {self.options[mail][to]}...".format(**locals()))
                p = subprocess.Popen(("/usr/sbin/sendmail", "-t", "-oi",), stdin=subprocess.PIPE)
                p.communicate(message.as_bytes())
            except Exception:
                self.logger.error("exception during subprocess.Popen(): {}".format(sys.exc_info()[1]))
                return False
            return True
    # }}}
    # {{{ _dbLoad(self, dbPath)
    def _dbLoad(self, dbPath):
        try:
            with open(dbPath, "r") as fileObject:
                db = json.load(fileObject)
        except FileNotFoundError:
            db = {}; pass;
        return db
    # }}}
    # {{{ _dbWrite(self, changeFlag, db, dbPath)
    def _dbWrite(self, changeFlag, db, dbPath):
        if changeFlag:
            with open(dbPath, "w") as fileObject:
                json.dump(db, fileObject)
    # }}}
    # {{{ _usage(self, argv0, options)
    def _usage(self, argv0, options):
        print(self.helpString.format(**locals()))
    # }}}
    # {{{ _wantListLoad(self, apiUrlBase, user)
    def _wantListLoad(self, apiUrlBase, user):
        apiUrl = "{}/users/{}/wants".format(apiUrlBase, user)
        while True:
            self.logger.debug("Fetching [4m{apiUrl}[0m...".format(**locals()))
            response = requests.get(apiUrl, headers={"User-Agent":self.userAgent})
            responseStatus = response.status_code
            if responseStatus == 200:
                wantList = response.json(); break;
            elif responseStatus == 429:
                self.logger.error("rate limit of 60 requests per minute exceeded, waiting 60 seconds (message: `{}')".format(response.json()["message"]))
                time.sleep(60)
            else:
                self.logger.error("non-successful status received, message: `{}'".format(response.json()["message"]))
                return None
        return [str(item["id"]) for item in wantList["wants"]]
    # }}}
    # {{{ synchronise(self)
    def synchronise(self):
        changeFlag, discogsDb, rc, releases = False, self._dbLoad(self.discogsDbPath), True, self.args
        while True:
            releasesUpdate = []
            for release in releases:
                data = self._dataFetch(self.apiUrlBase, release)
                changeFlag, discogsDb, rc = self._dataMerge(changeFlag, data, discogsDb, release)
                if rc:
                    if changeFlag:
                        releasesUpdate += [release]
                    self._dbWrite(changeFlag, discogsDb, self.discogsDbPath)
            self._dataChangeNotify(changeFlag, data, discogsDb, releasesUpdate)
            if self.options["daemonise"]:
                time.sleep(self.options["interval"])
            else:
                break
        return rc
    # }}}
    # {{{ __init__(self, argv): initialisation method
    def __init__(self, argv):
        options = self.optionsDefault.copy()
        optionsList, args = getopt(argv[1:], self.optionsString)
        for optionChar, optionArg in optionsList:
            optionName = self.optionsStringMap[optionChar[1:]]
            if type(self.optionsDefault[optionName]) is bool:
                options[optionName] = True
            elif type(self.optionsDefault[optionName]) is int:
                options[optionName] = int(optionArg)
            else:
                options[optionName] = optionArg
        if options["help"]:
            self._usage(argv[0], options); exit(0);
        elif (len(args) == 0) and (options["wantListUser"] is None):
            print("error: no release(s) specified", file=sys.stderr)
            self._usage(argv[0], options); exit(1);
        else:
            self.options = options
            logging.getLogger("requests").propagate = False
            self.logger = logging.getLogger(__name__)
            if self.options["verbose"]:
                logging.root.setLevel(logging.DEBUG)
            else:
                logging.root.setLevel(logging.INFO)
            loggingHandler = logging.StreamHandler(sys.stderr)
            loggingHandler.setFormatter(DiscogsUpdatesFormatter(not self.options["daemonise"]))
            self.logger.addHandler(loggingHandler)
            if self.options["wantListUser"] is not None:
                self.args = self._wantListLoad(self.apiUrlBase, self.options["wantListUser"])
                if self.args is None:
                    exit(1)
            else:
                self.args = args
            if self.options["mail"] is not None:
                self.options["mail"] = self.options["mail"].split(":")
                if len(self.options["mail"]) != 2:
                    print("error: invalid -m argument", file=sys.stderr)
                    self._usage(argv[0], options); exit(1);
                else:
                    self.options["mail"] = {"from":self.options["mail"][0], "to":self.options["mail"][1]}
    # }}}

if __name__ == "__main__":
    DiscogsUpdates = DiscogsUpdates(sys.argv)
    if DiscogsUpdates.options["daemonise"]:
        with daemon.DaemonContext():
            exit(0 if DiscogsUpdates.synchronise() else 1)
    else:
        exit(0 if DiscogsUpdates.synchronise() else 1)

# vim:expandtab foldmethod=marker sw=4 ts=4 tw=120
