#!/bin/sh

pop_IFS() { IFS="${_IFS}"; unset _IFS; };
push_IFS() { _IFS="${IFS}"; IFS="${1}"; };

# {{{ rc([-e], $_nflag, $_cmd, ...)
rc() {
	if [ "${1#-e}" != "${1}" ]; then
		local _eflag=1; shift;
	else
		local _eflag=0;
	fi;
	local _nflag="${1}" _cmd="${2}" _choice=0;
	shift 2;

	case "${_nflag}" in
	2)	eval printf \""[1m%s %s[0m\n"\" \"\${_cmd}\" \""${*}"\";
		printf "Run the above command? (y|N) "; read _choice; ;;
	1)	eval printf \""[90m%s %s[0m\n"\" \"\${_cmd}\" \""${*}"\";
		_choice="n"; ;;
	0)	eval printf \""[4m%s %s[0m\n"\" \"\${_cmd}\" \""${*}"\";
		_choice="y"; ;;
	*)	return 1; ;;
	esac;

	case "${_choice}" in
	[yY])	case "${_eflag}" in
		0) "${_cmd}" "${@}"; ;;
		1) eval "${_cmd}${*:+ ${*}}"; ;;
		esac; ;;
	*)	;;
	esac;
};
# }}}

# {{{ apps
rsync_app() {
	local _nflag="${1}" _Nflag="${2}" _path_dst="app" _path_src="/data/app";
	[ "${_Nflag}" -eq 1 ] || _Nflag="";
	rc "${_nflag}" rsync ${_Nflag:+-n} -e "adb shell" --blocking-io -aiPv --delete "exec:/${_path_src}/" "${_path_dst}/";
};

ls_app() {
	local _nflag="${1}" _Nflag="${2}" _fname_dst="app.lst" _path_src="app";
	[ "${_Nflag}" -eq 1 ] && _nflag=1;
	rc -e "${_nflag}" ls -alR \"\${_path_src}\" \> \"\${_fname_dst}\";
};
# }}}
# {{{ data
rsync_data() {
	local _nflag="${1}" _Nflag="${2}" _path_dst="data" _path_src="/data/data";
	[ "${_Nflag}" -eq 1 ] || _Nflag="";
	rc "${_nflag}" rsync ${_Nflag:+-n} -e "adb shell" --blocking-io -aiPv --delete --include-from="../RSYNC_INCLUDE_FROM.data" "exec:/${_path_src}/" "${_path_dst}/";
};

ls_data() {
	local _nflag="${1}" _Nflag="${2}" _fname_dst="data.lst" _path_src="data";
	[ "${_Nflag}" -eq 1 ] && _nflag=1;
	rc -e "${_nflag}" ls -alR \"\${_path_src}\" \> \"\${_fname_dst}\";
};
# }}}
# {{{ media
rsync_media() {
	local _nflag="${1}" _Nflag="${2}" _path_dst="media" _path_src="/data/media/0";
	[ "${_Nflag}" -eq 1 ] || _Nflag="";
	rc "${_nflag}" rsync ${_Nflag:+-n} -e "adb shell" -aiPv --blocking-io --delete --include-from="../RSYNC_INCLUDE_FROM.media" "exec:/${_path_src}/" "${_path_dst}/";
};

ls_media() {
	local _nflag="${1}" _Nflag="${2}" _fname_dst="media.lst" _path_src="media";
	[ "${_Nflag}" -eq 1 ] && _nflag=1;
	rc -e "${_nflag}" ls -alR \"\${_path_src}\" \> \"\${_fname_dst}\";
};
# }}}

# {{{ usage([$_rc=1])
usage() {
	local _rc="${1:-1}";
	printf "usage: %s [-A] [-a] [-c] [-d] [-m] [-n] [-N] <addr> <port> <code-pair> <port-pair>\n" "${0##*/}" >&2;
	printf "       -A......: sync everything (apps, data, media)\n" >&2;
	printf "       -a......: sync apps\n" >&2;
	printf "       -c......: confirm commands before running them\n" >&2;
	printf "       -d......: sync data\n" >&2;
	printf "       -m......: sync media\n" >&2;
	printf "       -n......: dry run\n" >&2;
	printf "       -N......: dry rsync run\n" >&2;
	exit "${_rc}";
};
# }}}

main() {
	local	_addr="" _aflag=0 _Aflag=0 _code_pair="" _device="" _dflag=0	\
		_nflag=0 _Nflag=0 _mflag=0 _opt="" _port="" _port_pair="";

	while getopts aAcdhmnN _opt; do
	case "${_opt}" in
	a)	_aflag=1; ;;
	A)	_aflag=1; _dflag=1; _mflag=1; ;;
	c)	_nflag=2; ;;
	d)	_dflag=1; ;;
	h)	usage 0; ;;
	m)	_mflag=1; ;;
	n)	_nflag=1; ;;
	N)	_Nflag=1; ;;
	*)	usage 1; ;;
	esac; done;
	shift $((${OPTIND}-1));

	if [ "${#}" -ne 4 ]; then
		printf "error: missing <addr> <port> <code-pair> <port-pair>\n" >&2; usage 2;
	else
		_addr="${1}"; _port="${2}" _code_pair="${3}" _port_pair="${4}";
	fi;

	push_IFS "
";	for _device in $(find . -maxdepth 1 -mindepth 1 -type d); do
		pop_IFS;
		_device="${_device#./}";
		(cd "${_device}";
		 trap 'pkill -f "adb .* fork-server "' ALRM EXIT HUP INT TERM USR1 USR2;
		 adb pair "${_addr}:${_port_pair}" "${_code_pair}" || exit "${?}";
		 adb connect "${_addr}:${_port}" || exit "${?}";
		 adb root || exit "${?}";
		 _rc=0;

		 if [ "${_aflag}" -eq 1 ]; then
		 	rsync_app "${_nflag}" "${_Nflag}"; [ "${?}" -ne 0 ] && _rc="${?}";
		 	ls_app "${_nflag}" "${_Nflag}"; [ "${?}" -ne 0 ] && _rc="${?}";
		 fi;
		 if [ "${_dflag}" -eq 1 ]; then
		 	rsync_data "${_nflag}" "${_Nflag}"; [ "${?}" -ne 0 ] && _rc="${?}";
		 	ls_data "${_nflag}" "${_Nflag}"; [ "${?}" -ne 0 ] && _rc="${?}";
		 fi;
		 if [ "${_mflag}" -eq 1 ]; then
			 rsync_media "${_nflag}" "${_Nflag}"; [ "${?}" -ne 0 ] && _rc="${?}";
			 ls_media "${_nflag}" "${_Nflag}"; [ "${?}" -ne 0 ] && _rc="${?}";
		 fi;
		 exit "${_rc}"
		);
		push_IFS "
";	done;
};

set +o errexit -o noglob -o nounset; main "${@}";
