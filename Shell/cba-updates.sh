#!/bin/sh

# {{{ Default variables
DEFAULT_COLOUR_DIST_UPGRADE="94";
DEFAULT_COLOUR_FAILURE="91";
DEFAULT_COLOUR_RDEPENDS="96";
DEFAULT_COLOUR_SERVICES="93";
DEFAULT_COLOUR_SUCCESS="32";
DEFAULT_COLOUR_TIMESTAMP="33";
DEFAULT_USER="toor";
# }}}
# {{{ Remote script variable
REMOTE_SCRIPT='
	fini() { local _log_fname="${1}"; echo "${rc_last:-0} fini"; cat "${_log_fname}"; rm -f "${_log_fname}"; };
	init() { dpkg_new_fnames=""; pkgs=""; pkgs_rdepends=""; pkgs_rdepends_services=""; rc=""; rc_last=""; log_fname="$(mktemp)" || exit 1; };
	status() { local _rc="${1}"; echo "${*}"; rc_last="${_rc}"; if [ "${_rc}" -ne 0 ]; then exit "${_rc}"; fi; };
	init; trap "fini \"${log_fname}\"" EXIT HUP INT QUIT TERM USR1 USR2;

	# apt-get -y update
	DEBIAN_FRONTEND=noninteractive apt-get -y update >>"${log_fname}" 2>&1;
	status "${?}" update;

	# apt-get -y dist-upgrade
	pkgs="$(DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::="--force-confold" dist-upgrade 2>&1)"; rc="${?}";
	printf "%s\n" "${pkgs}" >>"${log_fname}";
	pkgs="$(printf "%s\n" "${pkgs}"									|
		awk '\''
			$0 == "The following packages will be upgraded:" {m=1; next}
			m {if ($0 !~ /^  /) {m=0} else {print}}'\'')";
	pkgs="$(printf "%s\n" "${pkgs}"									|
		sed -ne "s/  */\n/gp" | sed -ne "/^ *$/d" -e "p" | paste -sd " ")";
	status "${rc}" dist-upgrade "${pkgs}";

	# apt-get -y autoremove --purge
	DEBIAN_FRONTEND=noninteractive apt-get -y autoremove --purge >>"${log_fname}" 2>&1;
	status "${?}" autoremove;

	# rm -f /var/cache/apt/archives/*.deb
	rm -f /var/cache/apt/archives/*.deb >>"${log_fname}" 2>&1;
	status "${?}" clean;

	if [ -n "${pkgs}" ]; then
		# apt-cache rdepends --installed
		pkgs_rdepends="$(apt-cache rdepends --installed ${pkgs} 2>&1)"; rc="${?}";
		printf "%s\n" "${pkgs_rdepends}" >>"${log_fname}";
		pkgs_rdepends="$(printf "%s\n" "${pkgs_rdepends}"					|
			sed -n -e "s/^\s\+|\?//" -e "/^Reverse Depends:\$/d" -e "/^lib/d" -e "p"	|
			sort | uniq | paste -sd " ")";
		status "${rc}" rdepends "${pkgs_rdepends}";

		# dpkg -l [ ... ] | grep -Eq "^(/etc/init.d|/lib/systemd/system)/"
		for pkg in ${pkgs_rdepends}; do
			if dpkg -L "${pkg}" 2>>"${log_fname}"						|
			   grep -Eq "^(/etc/init.d|/lib/systemd/system)/"; then
				pkgs_rdepends_services="${pkgs_rdepends_services:+${pkgs_rdepends_services} }${pkg}";
			fi;
		done;
		if [ -n "${pkgs_rdepends_services}" ]; then
			status 0 services "${pkgs_rdepends_services}";
		fi;

		# find /etc -name *.dpkg-new
		dpkg_new_fnames="$(find /etc -name *.dpkg-new 2>/dev/null | paste -d " " -s)";
		if [ -n "${dpkg_new_fnames}" ]; then
			status "${?}" dpkg-new "${dpkg_new_fnames}";
		fi;
	fi';
# }}}
# {{{ Private subroutines
logf() {
	local _fmt="${1}" _ts_fmt="%d-%^b-%Y %H:%M:%S"; shift;
	printf "[${DEFAULT_COLOUR_TIMESTAMP}m%s[0m ${_fmt}" "$(date +"${_ts_fmt}")" "${@}";
};

printf_rc() {
	local _colour="${1:-${DEFAULT_COLOUR_SUCCESS}}" _rc="${2}" _fmt="${3}"; shift 3;
	if [ "${_rc}" -eq 0 ]; then
		printf "[${_colour}m${_fmt}[0m" "${@}";
	else
		printf "[${DEFAULT_COLOUR_FAILURE}m${_fmt}[0m" "${@}";
	fi;
};
# }}}

update_host() {
	local	_host="${1}" _lflag="${2}" _user="${3}" _failfl=0 _log_data="" _log_fname=""\
		_rc_fifo_fl=0 _rc_fifo_fname="cba-updates.${1%%.}.fifo" _rc_fifo_rc=0;
	logf "%s:" "${_host}";
	if ! _log_fname="cba-updates.${_host%%.}_$(date +%Y%m%d).log"; then
		printf_rc "" 1 " [date(1) exited w/ non-zero status.]\n";
	elif ! rm -f "${_rc_fifo_fname}"\
	||   ! mkfifo "${_rc_fifo_fname}"; then
		printf_rc "" 1 " [failed to (re)create FIFO \`%s'.]\n" "${_rc_fifo_fname}";
	else	trap "rm -f \"${_rc_fifo_fname}\" >/dev/null 2>&1" EXIT HUP INT TERM USR1 USR2;
		{
			sleep 1; set +o errexit; exec 3>"${_rc_fifo_fname}";
			ssh	-l"${_user}"			\
				-oServerAliveinterval=60	\
				-T "${_host}"			\
				"${REMOTE_SCRIPT}" 2>/dev/null;
			echo "${?}" >&3;
		} | {
		exec 3<>"${_rc_fifo_fname}";
		while true; do
			if [ "${_rc_fifo_fl:-0}" -eq 0 ]; then
				_msg=""; read -r _msg <&3;
				if [ -n "${_msg}" ]; then
					_rc_fifo_fl=1; _rc_fifo_rc="${_msg}";
				fi;
			fi;
			if ! read -r _rc _type _msg; then
				break;
			else
				if [ "${_rc:-0}" -ne 0 ]; then
					_failfl=1;
				fi;
				case "${_type}" in
				autoremove)
						printf_rc "" "${_rc}" " %s" "${_type}"; ;;
				clean)
						printf_rc "" "${_rc}" " %s" "${_type}"; ;;
				dist-upgrade)
						printf_rc "${DEFAULT_COLOUR_DIST_UPGRADE}" "${_rc}" " %s(%s)" "${_type}" "${_msg}"; ;;
				dpkg-new)
						printf_rc "" "${_rc}" " %s(%s)" "${_type}" "${_msg}"; ;;
				rdepends)
						printf_rc "${DEFAULT_COLOUR_RDEPENDS}" "${_rc}" " %s(%s)" "${_type}" "${_msg}"; ;;
				services)
						printf_rc "${DEFAULT_COLOUR_SERVICES}" "${_rc}" " %s(%s)" "${_type}" "${_msg}"; ;;
				update)
						printf_rc "" "${_rc}" " %s" "${_type}"; ;;
				fini)		printf_rc "" "${_rc}" " %s" "[fetching log]";
						if [ "${_failfl:-0}" -eq 0 ]\
						&& [ "${_lflag:-0}" -eq 0 ]; then
							_log_fname="/dev/null";
						else
							touch "${_log_fname}";
						fi;
						while IFS= read -r _log_data; do
							printf "%s\n" "${_log_data}" >>"${_log_fname}";
						done; break; ;;
				*)		printf " [${DEFAULT_COLOUR_FAILURE}m?(rc=%s,type=%s,msg=%s)[0m" "${_rc}" "${_type}" "${_msg}"; break; ;;
				esac;
			fi;
		done;
		if [ "${_rc_fifo_rc}" -ne 0 ]; then
			printf " [${DEFAULT_COLOUR_FAILURE}m[ssh(1) exited w/ exit status %s.][0m\n" "${_rc_fifo_rc}";
		else
			printf ".\n";
		fi;
		};
		rm -f "${_rc_fifo_fname}"; trap - EXIT HUP INT TERM USR1 USR2;
	fi;
};

usage() {
	echo "usage: ${0} [-h] [-l] [-u user] [--] hosts..." >&2;
	echo "       -l.......: always save logs (defaults to save on failure only)" >&2;
	echo "       -u user..: username to login with (defaults to ${DEFAULT_USER})" >&2;
};

main() {
	local _host="" _hosts="" _lflag=0 _msg="" _opt="" _rc="" _type="" _user="${DEFAULT_USER}";
	while getopts hlu: _opt; do
	case "${_opt}" in
	h)	usage; exit 0; ;;
	l)	_lflag=1; ;;
	u)	_user="${OPTARG}"; ;;
	*)	usage; exit 1; ;;
	esac; done; shift $((${OPTIND}-1));
	if [ "${#}" -ge 1 ]; then
		_hosts="${*}";
	elif [ -e "${HOME}/.cba-updates.hosts" ]; then
		_hosts="$(cat "${HOME}/.cba-updates.hosts")";
	fi;
	for _host in ${_hosts}; do
		update_host "${_host}" "${_lflag}" "${_user}";
	done;
};

set -o errexit -o noglob -o nounset; main "${@}";

# vim:tw=0
