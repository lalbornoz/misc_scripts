#!/usr/bin/env python
# vim:fileencoding=utf-8
#
# KSCrawlerIRCBot.py (c) 2014 by Lucía Andrea Illanes Albornoz <lucia@luciaillanes.de>
# Originally based on [1].
#
# References:
# Fri Oct  3 19:41:45 CEST 2014 [1] MA3STR0/kimsufi-crawler · GitHub <https://github.com/MA3STR0/kimsufi-crawler>
#

import daemon
import json
import logging
from socket import socket, AF_INET, SOCK_STREAM
from tornado.gen import coroutine
from tornado.httpclient import AsyncHTTPClient
from tornado.ioloop import IOLoop, PeriodicCallback
from tornado.iostream import IOStream

class IRCBot(object):
# {{{ class IRCBot
	def __init__(self, config, logger, *args, **kwargs):
		self.config = config; self.logger = logger; self._connect();

	def _connect(self):
		self._socket = socket(AF_INET, SOCK_STREAM, 0)
		self._stream = IOStream(self._socket)
		self._stream.connect((self.config["irc_server_hname"], self.config["irc_server_port"]), self._onConnect)

	def _onConnect(self):
		self._stream.write(str("NICK %s\r\n" % self.config["irc_nick"]))
		self._stream.write(str("USER %s 0 0 :%s\r\n" % (self.config["irc_user"], self.config["irc_gecos"])))
		self._next()

	def _next(self):
		self._stream.read_until("\r\n", self._onIncoming)

	def _onIncoming(self, line):
		tokens = line.split(" ")
		if not tokens:
			return
		if tokens[0].startswith(":"):
			from_nick = tokens[0][1:].split("!")[0]
			try:
				from_user = tokens[0][1:].split("!")[1].split("@")[0]
				from_hname = tokens[0][1:].split("@")[1]
			except IndexError:
				from_user = ""; from_hname = ""; pass;
			tokens.remove(tokens[0])
		else:
			from_nick = ""; from_user = ""; from_hname = "";
		last_token = [token for token in tokens if token.startswith(":")]
		if last_token:
			last_token_idx = tokens.index(last_token[0])
			tokens = tokens[0:last_token_idx] + [" ".join(tokens[last_token_idx:])[1:]]
			if tokens[-1][-2:] == "\r\n":
				tokens[-1] = tokens[-1][:-2]
		tokens[0] = tokens[0].upper()
		for handler in self.__class__.__dict__:
			if handler == ("_handle_" + tokens[0]):
				self.__class__.__dict__[handler](self, from_nick, from_user, from_hname, tokens[1:])
		self._next()
# }}}

class KSCrawler(object):
# {{{ class KSCrawler
	def __init__(self, config, logger, *args, **kwargs):
		self.config = config; self._STATES = {};
		PeriodicCallback(self._run_crawler, self.config["crawler_frequency"] * 1000).start()

	@coroutine
	def _run_crawler(self):
		http_client = AsyncHTTPClient()
		response = yield http_client.fetch(self.config["ks_url"])
		response_json = json.loads(response.body.decode("utf-8"))
		availability = response_json["answer"]["availability"]
		for item in availability:
			if self.config["ks_server_types"].get(item["reference"]) in self.config["crawler_servers"]:
				zones = [e["zone"] for e in item["zones"]
					 if e["availability"] not in ["unknown", "unavailable"]]
				if [z for z in self.config["crawler_zones"] if z in zones]:
					server = self.config["ks_server_types"][item["reference"]]
					text = "Server %s is available in %s" \
						% (server, ", ".join([self.config["ks_datacenters"][zone] for zone in zones]))
					message = {
						"Text": text,
						"Title": "Server %s available" % server,
						"URL": "http://www.kimsufi.com/fr/index.xml"
					}
					state_id = "%s_available_in_%s" % (server, "+".join(zones))
					self._update_state(state_id, True, message)
				else:
					state_id = ""; self._update_state(state_id, False)

	def _update_state(self, state, value, message=False):
		if state not in self._STATES:
			self._STATES[state] = False
		if value is not self._STATES[state]:
			self.logger.info("State change - %s:%s", state, value)
		if value and not self._STATES[state]:
			self._handle_stateChange(message)
		self._STATES[state] = value

	def _handle_stateChange(self, message):
		pass
# }}}

class KSCrawlerIRCBot(IRCBot, KSCrawler):
# {{{ class KSCrawlerIRCBot
	def __init__(self, *args, **kwargs):
		IRCBot.__init__(self, *args, **kwargs)
		KSCrawler.__init__(self, *args, **kwargs)

	def _handle_001(self, from_nick, from_user, from_hname, tokens):
		self.logger.info("Received RPL_WELCOME from " + self.config["irc_server_hname"])
		for channel in self.config["irc_channels"]:
			self.logger.info("Joining channel " + channel)
			self._stream.write(str("JOIN %s\r\n" % channel))
		pass

	def _handle_PING(self, from_nick, from_user, from_hname, tokens):
		self.logger.info("Received PING from %s, sending PONG." % self.config["irc_server_hname"])
		self._stream.write(str("PONG :%s\r\n" % tokens[0]))
		pass

	def _handle_stateChange(self, message):
		for channel in self.config["irc_channels"]:
			for key in message:
				self._stream.write(str("PRIVMSG %s :%c%s: %s\r\n" % (channel, key[0].upper(), key[1:], message[key])))
# }}}

if __name__ == "__main__":
	with open("KSCrawlerIRCBot.json", "r") as configfile:
		config = json.loads(configfile.read())
	logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
	logger = logging.getLogger(__name__)
	with daemon.DaemonContext():
		kcib = KSCrawlerIRCBot(config, logger)
		IOLoop.instance().start()

# vim:ts=8 sw=8 tw=120 noexpandtab foldmethod=marker fileencoding=utf-8
