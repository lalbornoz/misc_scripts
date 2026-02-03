#!/usr/bin/env python3
#
# OpenWeatherMap.py -- Obtain daily weather from OpenWeatherMap.org
# Copyright (c) 2018, 2022, 2023, 2026 Lucía Andrea Illanes Albornoz <lucia@luciaillanes.de>
# This project is licensed under the terms of the MIT licence.
#
# {{{ ~/.tmux.conf integration example
# HOME_CITY="Hamburg"
# HOME_COUNTRY="Germany"
# set-option -g status-interval		60
# set-option -g status-right		"#[fg=brightblue]#(~/.local/bin/OpenWeatherMap.py -c $HOME_CITY -C $HOME_COUNTRY -p tmux -P \"{white}{u}{Weather condition}{nu} {lgreen}{Feels like} {white}{Temperature} {lcyan}{Dew point}{white} {b}{Humidity}{nb} {Wind (speed)}\" -D \"{grey}{u}{Weather condition}{nu} {Feels like} {Temperature} {Dew point} {b}{Humidity}{nb} {Wind (speed)} | \") #[fg=$TMUX_COLOUR]#H %H:%M:%S %a %d-%b-%y"
# set-option -g status-right-length	115
# }}}
#

from datetime import datetime
from getopt import getopt
from OpenWeatherMapApiKey import OpenWeatherMapApiKey
import hashlib, json, os, requests, sys, time

# {{{ _capitalise(oldString)
def _capitalise(oldString):
    if len(oldString) > 1:
        return oldString[0].upper() + oldString[1:]
    else:
        return oldString
# }}}
# {{{ _flattenDict(oldDict, parentKey, sepChar)
def _flattenDict(oldDict, parentKey, sepChar):
    flatDict = {}
    for oldKey, oldVal in oldDict.items():
        if type(oldVal) is dict:
            flatDict = {**flatDict, **_flattenDict(oldVal, oldKey, sepChar)}
        elif type(oldVal) is list:
            for oldValIdx in range(len(oldVal)):
                flatDict = {**flatDict, **_flattenDict(oldVal[oldValIdx], oldKey + "." + str(oldValIdx), sepChar)}
        else:
            flatDict[oldKey if parentKey == "" else parentKey + sepChar + oldKey] = oldVal
    return flatDict
# }}}

class OpenWeatherMap(object):
    """Obtain daily weather from OpenWeatherMap.org"""

    # {{{ Class attributes
    apiUrlBase = "https://api.openweathermap.org/data/2.5/weather"
    apiUrlBaseForecast = "https://api.openweathermap.org/data/2.5/forecast"
    attrIgnore = [
        "base",
        "cnt",
        "cod",
        "main.temp_kf",
        "message",
        "sys.id",
        "sys.message",
        "sys.type"]
    attrSuffixes = {
        "clouds.all":"%",
        "coord.lat":"°",
        "coord.lon":"°",
        "extra.dew_point":"°",
        "main.feels_like":"°",
        "main.grnd_level":"hPa",
        "main.sea_level":"hPa",
        "main.humidity":"%",
        "main.pressure":" hPa",
        "main.temp":"°",
        "main.temp_min":"°",
        "main.temp_max":"°",
        "rain.1h":"mm",
        "rain.3h":"mm",
        "snow.1h":"mm",
        "snow.3h":"mm",
        "wind.deg":"°",
        "wind.speed":" km/h"}
    attrTitles = {
        "city.coord.lat":"City geo location, latitude",
        "city.coord.lon":"City geo location, longitude",
        "city.country":"Country code",
        "city.id":"City ID",
        "city.name":"City name",
        "city.population":"City population",
        "city.sunrise":"Sunrise time in UTC",
        "city.sunset":"Sunset time in UTC",
        "city.timezone":"Shift in seconds from UTC",
        "clouds.all":"Cloudiness",
        "coord.lat":"City geo location, latitude",
        "coord.lon":"City geo location, longitude",
        "dt":"Timestamp in UTC",
        "dt_txt":"Time of data forecasted, ISO, UTC",
        "id":"City ID",
        "extra.dew_point":"Dew point",
        "main.feels_like":"Feels like",
        "main.humidity":"Humidity",
        "main.pressure":"Pressure",
        "main.grnd_level":"Atmospheric pressure on the ground level",
        "main.sea_level":"Atmospheric pressure on the sea level",
        "main.temp":"Temperature",
        "main.temp_min":"Temperature (min.)",
        "main.temp_max":"Temperature (max.)",
        "name":"Location",
        "pop":"Probability of precipitation",
        "rain.1h":"Rain volume for the last 1 hour",
        "rain.3h":"Rain volume for the last 3 hours",
        "snow.1h":"Snow volume for the last 1 hour",
        "snow.3h":"Snow volume for the last 3 hours",
        "sys.country":"Country code",
        "sys.pod":"Part of the day (n - night, d - day)",
        "sys.sunrise":"Sunrise time in UTC",
        "sys.sunset":"Sunset time in UTC",
        "timezone":"Shift in seconds from UTC",
        "visibility":"Visibility",
        "weather.0.icon":"Weather icon id",
        "weather.0.id":"Weather condition id",
        "weather.0.main":"Weather condition",
        "weather.0.description":"Weather description",
        "wind.deg":"Wind (degree)",
        "wind.gust":"Wind (gust)",
        "wind.speed":"Wind (speed)"}

    attrAnsi = {
        "b":"\x1b[1m",
        "bold":"\x1b[1m",
        "nb":"\x1b[22m",
        "nobold":"\x1b[22m",
        "nounderline":"\x1b[24m",
        "nu":"\x1b[24m",
        "u":"\x1b[4m",
        "underline":"\x1b[4m"}
    attrAnsiColours = {
        "black":"\x1b[30m",
        "red":"\x1b[31m",
        "green":"\x1b[32m",
        "yellow":"\x1b[33m",
        "blue":"\x1b[34m",
        "magenta":"\x1b[35m",
        "cyan":"\x1b[36m",
        "white":"\x1b[37m",
        "grey":"\x1b[90m",
        "lred":"\x1b[91m",
        "lgreen":"\x1b[92m",
        "lyellow":"\x1b[93m",
        "lblue":"\x1b[94m",
        "lmagenta":"\x1b[95m",
        "lcyan":"\x1b[96m",
        "lwhite":"\x1b[97m",

        "bgblack":"\x1b[40m",
        "bgred":"\x1b[41m",
        "bggreen":"\x1b[42m",
        "bgyellow":"\x1b[43m",
        "bgblue":"\x1b[44m",
        "bgmagenta":"\x1b[45m",
        "bgcyan":"\x1b[46m",
        "bgwhite":"\x1b[47m",
        "bggrey":"\x1b[100m",
        "bglred":"\x1b[101m",
        "bglgreen":"\x1b[102m",
        "bglyellow":"\x1b[103m",
        "bglblue":"\x1b[104m",
        "bglmagenta":"\x1b[105m",
        "bglcyan":"\x1b[106m",
        "bglwhite":"\x1b[107m"}
    attrTmux = {
        "b":"#[bold]",
        "bold":"#[bold]",
        "nb":"#[nobold]",
        "nobold":"#[nobold]",
        "nounderline":"#[nounderscore]",
        "nu":"#[nounderscore]",
        "u":"#[underscore]",
        "underline":"#[underscore]"}
    attrTmuxColours = {
        "black":"#[fg=black]",
        "red":"#[fg=red]",
        "green":"#[fg=green]",
        "yellow":"#[fg=yellow]",
        "blue":"#[fg=blue]",
        "magenta":"#[fg=magenta]",
        "cyan":"#[fg=cyan]",
        "white":"#[fg=white]",
        "grey":"#[fg=grey]",
        "lred":"#[fg=brightred]",
        "lgreen":"#[fg=brightgreen]",
        "lyellow":"#[fg=brightyellow]",
        "lblue":"#[fg=brightblue]",
        "lmagenta":"#[fg=brightmagenta]",
        "lcyan":"#[fg=brightcyan]",
        "lwhite":"#[fg=brightwhite]",

        "bgblack":"#[bg=black]",
        "bgred":"#[bg=red]",
        "bggreen":"#[bg=green]",
        "bgyellow":"#[bg=yellow]",
        "bgblue":"#[bg=blue]",
        "bgmagenta":"#[bg=magenta]",
        "bgcyan":"#[bg=cyan]",
        "bgwhite":"#[bg=white]",
        "bggrey":"#[bg=grey]",
        "bglred":"#[bg=brightred]",
        "bglgreen":"#[bg=brightgreen]",
        "bglyellow":"#[bg=brightyellow]",
        "bglblue":"#[bg=brightblue]",
        "bglmagenta":"#[bg=brightmagenta]",
        "bglcyan":"#[bg=brightcyan]",
        "bglwhite":"#[bg=brightwhite]"}

    helpString = """usage: {argv0} [-h]
       [-a seconds] [-c city] [-C country] [-C dname] [-d days] [-f]
       [-l] [-L] [-p list|tmux] [-P fmt] [-t country] [-T dname]
       [-u imperial|metric] [-v]

       -h..................: show this screen
       -a seconds..........: purge cached data after specified amount of seconds (defaults to: {self.optionsDefault[purgeAfter]})
       -c city.............: specifies location city
       -C country..........: specifies location country
       -d days.............: specifies number of days to print forecast for (defaults to: {self.optionsDefault[forecastDays]})
       -D fmt..............: specifies output format string to iteratively print non-current day forecasts with (defaults to: {self.optionsDefault[forecastFmt]})
       -f..................: force (re)fetch from OpenWeatherMap.org (defaults to: {self.optionsDefault[forceFetch]})
       -l..................: list available OpenWeatherMap.org API attribute titles available for usage in -F and exit
       -L..................: list available ANSI (str format) or tmux (tmux format) attributes available for usage in -F and exit
       -p list|str|tmux....: specifies output format (defaults to {self.optionsDefault[outputFormat]})
       -P fmt..............: specifies str|tmux output format string (defaults to {self.optionsDefault[formatString]})
       -t imperial|metric..: specifies imperial or metric units (defaults to {self.optionsDefault[units]})
       -T dname............: specifies cache directory pathname
       -v..................: increase verbosity (defaults to: {self.optionsDefault[verbose]})"""

    optionsDefault = {
        "cachePathBase":os.path.expanduser(os.path.join("~", ".cache", "OpenWeatherMap")),
        "city":None, "country":None, "forceFetch":False, "forecastDays":1,
        "forecastFmt":"{grey}{u}{Weather condition}{nu} {Feels like} {Temperature} {Dew point} {Humidity} | ",
        "formatString":"{white}{u}{Weather condition}{nu} {lgreen}{Feels like} {white}{Temperature} {lcyan}{Dew point} {white}{b}{Humidity}{nb}",
        "help":False, "listAnsi":False, "listAttrs":False, "outputFormat":"list",
        "purgeAfter":900, "units":"metric", "verbose":False}
    optionsString = "a:c:C:d:D:fhlLp:P:t:u:v"
    optionsStringMap = {
        "a":"purgeAfter", "c":"city", "C":"country", "d":"forecastDays",
        "D":"forecastFmt", "f":"forceFetch", "h":"help", "l":"listAttrs",
        "L":"listAnsi", "p":"outputFormat", "P":"formatString", "t":"cachePathBase",
        "u":"units", "v":"verbose"}
    # }}}

    # {{{ _getData(self, apiUrlBase, cachePathBase, city, country, forceFetch, units, isSingle=True)
    def _getData(self, apiUrlBase, cachePathBase, city, country, forceFetch, units, isSingle=True):
        cacheKey = "{}\0{}\0{}\0{}\0{}\0".format(apiUrlBase, city, country, time.strftime("%d%m%Y"), units)
        cacheFileName = hashlib.sha256(cacheKey.encode()).hexdigest()
        cacheFilePathName = os.path.join(cachePathBase, cacheFileName)
        self._purgeCache(cacheFilePathName, cachePathBase)
        rc = False
        if not forceFetch:
            rc, status, data = self._getDataCache(apiUrlBase, cacheFilePathName)
        if not rc:
            rc, status, data = self._getDataFetch(apiUrlBase, cacheFilePathName, city, country, units)
        return self._processDataList(data, rc, status)
    # }}}
    # {{{ _getDataCache(self, apiUrlBase, cacheFilePathName)
    def _getDataCache(self, apiUrlBase, cacheFilePathName):
        if not os.path.isdir(os.path.dirname(cacheFilePathName)):
            os.makedirs(os.path.dirname(cacheFilePathName))
        if not os.path.exists(cacheFilePathName):
            return False, None, None
        else:
            with open(cacheFilePathName, "r") as fileObject:
                data = json.load(fileObject)
            return True, 200, data
    # }}}
    # {{{ _getDataFetch(self, apiUrlBase, cacheFilePathName, city, country, units)
    def _getDataFetch(self, apiUrlBase, cacheFilePathName, city, country, units):
        apiUrl = "{}?APPID={}&units={}&q={},+{}".format(
            apiUrlBase, OpenWeatherMapApiKey.openWeatherMapApiKey, units, city, country)
        self._log("Fetching [4m{apiUrl}[0m...".format(**locals()), isVerbose=True)
        data, rc = requests.get(apiUrl).json(), False
        if int(data["cod"]) == 200:
            with open(cacheFilePathName, "w+") as fileObject:
                json.dump(data, fileObject)
            rc = True
        return rc, int(data["cod"]), data
    # }}}
    # {{{ _purgeCache(self, cacheFilePathName, cachePathBase)
    def _purgeCache(self, cacheFilePathName, cachePathBase):
        if os.path.isdir(cachePathBase):
            for cacheFileName in os.listdir(cachePathBase):
                if  os.path.isfile(os.path.join(cachePathBase, cacheFileName)):
                    cacheFileMTime = int(os.path.getmtime(os.path.join(cachePathBase, cacheFileName)))
                    timeNow = int(time.time())
                    if  timeNow > cacheFileMTime    \
                    and ((timeNow - cacheFileMTime) >= int(self.options["purgeAfter"])):
                        os.remove(os.path.join(cachePathBase, cacheFileName))
    # }}}

    # {{{ _log(self, msg): Log single message to std{err,out} w/ timestamp
    def _log(self, msg, isError=False, isVerbose=False):
        if isError:
            print("{} [91mError: {}[0m".format(time.strftime("%d-%^b-%Y %H:%M:%S"), msg), file=sys.stderr)
        elif isVerbose and self.options["verbose"]:
            print("{} [36m{}[0m".format(time.strftime("%d-%^b-%Y %H:%M:%S"), msg))
        elif not isVerbose:
            print("{} {}".format(time.strftime("%d-%^b-%Y %H:%M:%S"), msg))
    # }}}

    # {{{ _printAsList(self, attrsPretty, dayCount, dayMax)
    def _printAsList(self, attrsPretty, dayCount, dayMax):
        attrsPadding, output = 0, ""
        for attrKey, attrValue in attrsPretty.items():
            attrsPadding = max(attrsPadding, len(attrKey))
        for attrKey, attrValue in sorted(attrsPretty.items(), key=lambda kv: kv[0]):
            output += (("{:" + str(attrsPadding) + "}: {}\n").format(attrKey, attrValue))
        return output
    # }}}
    # {{{ _printAsStr(self, attrsPretty, dayCount, dayMax)
    def _printAsStr(self, attrsPretty, dayCount, dayMax):
        return (self.options["formatString"] if ((self.options["forecastDays"] == 1) or (dayCount == dayMax))   \
                    else self.options["forecastFmt"])                                                           \
                        .format(**{**attrsPretty, **self.attrAnsi, **self.attrAnsiColours})
    # }}}
    # {{{ _printAsTmux(self, attrsPretty, dayCount, dayMax)
    def _printAsTmux(self, attrsPretty, dayCount, dayMax):
        return (self.options["formatString"] if ((self.options["forecastDays"] == 1) or (dayCount == dayMax))   \
                    else self.options["forecastFmt"])                                                           \
                        .format(**{**attrsPretty, **self.attrTmux, **self.attrTmuxColours})
    # }}}

    # {{{ _processDataList(self, data_, rc, status)
    def _processDataList(self, data_, rc, status):
        if rc:
            data, dayLast = [], None
            if self.options["forecastDays"] > 1:
                for n in range(0, len(data_["list"])):
                    dt = datetime.fromtimestamp(data_["list"][n]["dt"])
                    if (dayLast is not None) and (dayLast == dt.day):
                        continue
                    else:
                        dayLast = dt.day
                        data += [{**data_, **(data_["list"][n])}]
                        data[-1]["extra"] = {}
                        data[-1]["extra"]["dew_point"] =        \
                            round((data[-1]["main"]["temp"] -   \
                                ((100 - data[-1]["main"]["humidity"]) / 5.0)), 2)
                        if  ("wind" in data[-1])                \
                        and ("speed" in data[-1]["wind"]):
                            data[-1]["wind"]["speed"] =         \
                                    round((data[-1]["wind"]["speed"] * 3.6), 2)
                data = data[0:self.options["forecastDays"]]
            else:
                data = [data_]
                data[-1]["extra"] = {}
                data[-1]["extra"]["dew_point"] =        \
                    round((data[-1]["main"]["temp"] -   \
                        ((100 - data[-1]["main"]["humidity"]) / 5.0)), 2)
        else:
            data_ = []
        return rc, status, data
    # }}}
    # {{{ _processItem(self, attrsDict, attrsFlatDict, attrsPretty)
    def _processItem(self, attrsDict, attrsFlatDict, attrsPretty):
        for attrKey, attrValue in attrsFlatDict.items():
            if attrKey in ["weather.0.description", "weather.0.main"]:
                attrsDict[attrKey] = _capitalise(attrsFlatDict[attrKey])
            else:
                attrsDict[attrKey] = attrValue

        for attrKey, attrValue in attrsDict.items():
            if attrKey in self.attrTitles:
                attrsPretty[self.attrTitles[attrKey]] = str(attrValue)
                if attrKey in self.attrSuffixes:
                    attrsPretty[self.attrTitles[attrKey]] += self.attrSuffixes[attrKey]
            elif (attrKey not in self.attrIgnore)   \
            and  (not attrKey.startswith("list.")):
                print("Warning: title string not found for key {}".format(attrKey), file=sys.stderr)
    # }}}

    # {{{ _usage(self, argv0, options)
    def _usage(self, argv0, options):
        print(self.helpString.format(**locals()), file=sys.stderr)
    # }}}
    # {{{ _usageListAttributes(self, options)
    def _usageListAttributes(self, options):
        print("OpenWeather.org API attributes:")
        attrsPadding = 0
        for attrKey, attrTitle in self.attrTitles.items():
            attrsPadding = max(attrsPadding, len(attrTitle))
        for attrKey, attrTitle in sorted(self.attrTitles.items(), key=lambda kv: kv[1]):
            print(("{:" + str(attrsPadding) + "} (API attribute key: {})").format(attrTitle, attrKey))
    # }}}
    # {{{ _usageListAttributesAnsiTmux(self, options)
    def _usageListAttributesAnsiTmux(self, options):
        if options["outputFormat"] in ["list", "str"]:
            items, itemsColours, title = self.attrAnsi.items(), self.attrAnsiColours.items(), "ANSI attributes"
        elif options["outputFormat"] == "tmux":
            items, itemsColours, title = self.attrTmux.items(), self.attrTmuxColours.items(), "tmux attributes"
        else:
            return

        print(title + ":")
        attrsPadding = 0
        for attrKey, attrEsc in items:
            attrsPadding = max(attrsPadding, len(attrKey))
        for attrKey, attrEsc in itemsColours:
            attrsPadding = max(attrsPadding, len(attrKey))
        for attrKey, _ in sorted(items, key=lambda kv: kv[0]):
            attrEsc = self.attrAnsi[attrKey]
            print(("{}{:" + str(attrsPadding) + "}{}").format(attrEsc, attrKey, "\x1b[0m"))
        print("")
        for attrKey, _ in sorted(itemsColours, key=lambda kv: kv[0]):
            attrEsc = self.attrAnsiColours[attrKey]
            print(("{}{:" + str(attrsPadding) + "}{}").format(attrEsc, attrKey, "\x1b[0m"))
    # }}}

    # {{{ synchronise(self)
    def synchronise(self):
        if self.options["units"] == "imperial":
            self.attrSuffixes["wind.speed"] = " mph"
        elif self.options["units"] == "metric":
            self.attrSuffixes["wind.speed"] = " km/h"

        rc, status, data = self._getData(
            self.apiUrlBase if (self.options["forecastDays"] == 1) else self.apiUrlBaseForecast,
            self.options["cachePathBase"],
            self.options["city"],
            self.options["country"],
            self.options["forceFetch"],
            self.options["units"],
            (self.options["forecastDays"] == 1))

        if rc:
            dayCount, dayMax, output = 0, len(data), []
            if self.options["outputFormat"] in ["str", "tmux"]:
                data.reverse()

            for data in data:
                dayCount += 1
                attrsDict, attrsFlatDict, attrsPretty = {}, _flattenDict(data, "", "."), {}
                self._processItem(attrsDict, attrsFlatDict, attrsPretty)

                if self.options["outputFormat"] == "list":
                    output += [self._printAsList(attrsPretty, dayCount, dayMax)]
                    output += "\n"
                elif self.options["outputFormat"] == "str":
                    output += [self._printAsStr(attrsPretty, dayCount, dayMax)]
                elif self.options["outputFormat"] == "tmux":
                    output += [self._printAsTmux(attrsPretty, dayCount, dayMax)]
                else:
                    self._log("unknown output format `{}'".format(self.options["outputFormat"]), isError=True)
                    rc = 1

            for outputNum in range(len(output)):
                print(output[outputNum], end="")
            if len(output):
                print("")
        else:
            self._log("non-successful status `{}' received, message: `{}'".format(status, data), isError=True)
        return rc == 0
    # }}}

    #
    # __init__(self, argv): initialisation method
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
        elif options["listAnsi"] or options["listAttrs"]:
            if options["listAttrs"]:
                self._usageListAttributes(options)
            if options["listAnsi"]:
                if options["listAttrs"]:
                    print("")
                self._usageListAttributesAnsiTmux(options)
            exit(0)
        elif options["city"] is None    \
        or   options["country"] is None:
            if options["city"] is None:
                print("error: missing city", file=sys.stderr)
            if options["country"] is None:
                print("error: missing country", file=sys.stderr)
            self._usage(argv[0], options); exit(0);
        else:
            self.options = options

if __name__ == "__main__":
    exit(OpenWeatherMap(sys.argv).synchronise())

# vim:expandtab foldmethod=marker sw=4 ts=4 tw=120
