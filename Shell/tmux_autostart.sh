#!/bin/sh

: ${TMUX_AUTOSTART_GROUP:="users_tmux"};
: ${TMUX_NETNS_NAME:=""};

tmux_autostart() {
	local _cgroup="" _dname="" _uname="";
	if [ -e "/etc/default/tmux_autostart" ]; then
		if ! . "/etc/default/tmux_autostart"; then
			printf "Error: failed to source \`/etc/default/tmux_autostart'." >&2; exit 1;
		fi;
	fi;
	if ! [ -x "`which tmux 2>/dev/null`" ]; then
		printf "tmux(1) not found in \${PATH} (${PATH}), exiting.\n" >&2; return 1;
	else	printf "Autostarting tmux (1) sessions:";
		for _uname in $(getent group "${TMUX_AUTOSTART_GROUP}" | awk -F: '{gsub(/,/," ",$NF); print $NF}'); do
			_dname="$(getent passwd "${_uname}" | awk -F: '{print $6}')";
			_cgroup="users/${_uname}";
			if [ -r "${_dname}/.tmux_`hostname -s`_autostart.conf" ]; then
				if [ -n "${TMUX_NETNS_NAME:-}" ]; then
					ip	netns exec vpn	\
					su	-l "${_uname}"	\
						-c "tmux -f .tmux_`hostname -s`_autostart.conf start-server";
				else	su	-l "${_uname}"	\
						-c "tmux -f .tmux_`hostname -s`_autostart.conf start-server";
				fi;
				if [ "${?:-0}" -eq 0 ]; then
					printf " ${_uname}";
				fi;
			fi;
		done;
		printf "\n";
	fi;
};

set +o errexit -o noglob -o nounset; tmux_autostart "${@}";

# vim:tw=0
