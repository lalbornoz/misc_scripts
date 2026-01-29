#!/usr/bin/env perl
# $Id$

use 5.10.0; use strict; use warnings;
local $/; $_ = <>;
s,\004([:;?<=>23578]/|[cegi]),,sg;			# Irssi: ^D
#s,\003((1[0-5]|0?[0-9])(\,(1[0-5]|0?[0-9]))?|),,sg;	# mIRC: ^C
#s,\002|\x0f|\x1f,,sg;					# mIRC: ^B, ^O, ^_
s,\007,,sg;						# BEL
s,^([.:\d]+\s+)<([ %@^&~+])(?:\003(?:1[0-5]|0?[0-9])),$1<$2,msg;

print;

# vim:ts=8 sw=8 tw=80 noexpandtab foldmethod=marker
