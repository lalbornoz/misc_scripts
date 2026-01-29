#!/bin/sh

do_rsync() {
	local	_Lflag="${1}" _yflag="${2}" _rsync_args_extra="${3}" _src="${4}" target="${5}"	\
		_dst="" _log_fname="" _pwd_old="${PWD}"; _rc=0;

	if ! _dst="$(mount | awk '$3 ~ /\/'"${_target}"'\/*$/ { print $3 }')"\
	|| [ "${_dst:+1}" != 1 ]; then
		if [ -e "${HOME}/.ssh/config" ]\
		&& grep -Eq '^\s*\bHost\b.+\b'"${_target}"'\b' "${HOME}/.ssh/config";
		then
			_dst="${_target}:";
		else
			echo "error: target \`${_target}' neither mounted locally nor SSH host" >&2;
			_rc=1;
		fi;
	fi;

	if [ "${_rc}" -eq 0 ]\
	&& cd "${_src}"; then
		if [ "${_Lflag}" -eq 0 ]; then
			_log_fname="rsync_${_target}-${USER}@$(hostname -f)-$(date +%d%m%Y-%H%M%S).log";
			printf "" > "${_log_fname}";
		fi;

		rc "${_log_fname}" "${_yflag}" rsync					\
			-aiPv --delete							\
			${_rsync_args_extra}						\
				--include-from="${HOME}/.RSYNC_INCLUDE_FROM.${_target}"	\
			. "${_dst}";

		cd "${_pwd_old}";
	fi;

	return "${_rc}";
};

rc() {
	local _choice="" _log_fname="${1}" _yflag="${2}" _cmd="${3}";
	shift 3;

	if [ "${_yflag}" -eq 0 ]; then
		printf "Run command: %s %s? (y|N) " "${_cmd}" "${*}";
		read _choice;
	else
		_choice="y";
	fi;

	case "${_choice}" in
	[yY])	set +o errexit;
		if [ "${_log_fname:+1}" = 1 ]; then
			"${_cmd}" "${@}" 2>&1 | tee -a "${_log_fname}";
		else
			"${_cmd}" "${@}";
		fi;
		set -o errexit; ;;
	*)	return 0; ;;
	esac;
};

usage() {
	local _rc="${1}" _msg="${2:-}";

	if [ "${_msg:+1}" = 1 ]; then
		printf "%s\n" "${_msg}" >&2;
	fi;

	echo "usage: ${0} [-c] [-d dest] [-h] [-L] [-n] [-s <limit>] [-S <source>] [-y] [--] target[..]" >&2;
	echo "       -c...........: pass -c to rsync" >&2;
	echo "       -h...........: show this screen" >&2;
	echo "       -L...........: do not create log file" >&2;
	echo "       -n...........: dry run" >&2;
	echo "       -s <limit>...: force bandwidth limit of <limit>" >&2;
	echo "       -S <source>..: specify source directory (defaults to: ${HOME})" >&2;
	echo "       -y...........: automatic yes to prompts" >&2;

	exit "${_rc}";
};

main() {
	local	_cflag=0 _Lflag=0 _nflag=0 _opt="" _rc=0	\
		_rsync_args_extra="" _src="${HOME}" _target="" _yflag=0;

	while getopts chLns:S:y _opt; do
	case "${_opt}" in
	c)	_cflag=1; _rsync_args_extra="${_rsync_args_extra:+${_rsync_args_extra} }-c"; ;;
	L)	_Lflag=1; ;;
	n)	_nflag=1; _rsync_args_extra="${_rsync_args_extra:+${_rsync_args_extra} }-n"; ;;
	s)	_sflag=1; _rsync_args_extra="${_rsync_args_extra:+${_rsync_args_extra} }--bwlimit=${OPTARG}"; ;;
	S)	_src="${1}"; ;;
	y)	_yflag=1; ;;
	*)	usage 1; ;;
	esac; done;
	shift $((${OPTIND}-1));

	if [ "${#}" -eq 0 ]; then
		usage 1 "missing target";
	else
		while [ "${#}" -gt 0 ]; do
			_target="${1}"; shift;
			do_rsync						\
				"${_Lflag}" "${_yflag}" "${_rsync_args_extra}"	\
				"${_src}" "${_target}";
			_rc="${?}";
			if [ "${_rc}" -ne 0 ]; then
				break;
			fi;
		done;
		exit "${_rc}";
	fi;
};

set -o errexit -o noglob -o nounset; main "${@}";
