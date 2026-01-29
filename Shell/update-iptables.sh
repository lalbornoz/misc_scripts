#!/bin/sh

# {{{ Globals
RTL_LOG_LVL=0;
RTL_LOG_MSG_FATAL_COLOUR=91;		# Bright red
RTL_LOG_MSG_WARNING_COLOUR=31;		# Dark red
RTL_LOG_MSG_SUCCESS_COLOUR=33;		# Dark yellow
RTL_LOG_MSG_SUCCESS_END_COLOUR=32;	# Dark green
RTL_LOG_MSG_INFO_COLOUR=93;		# Bright yellow
RTL_LOG_MSG_INFO_END_COLOUR=92;		# Bright green
RTL_LOG_MSG_NOTICE_COLOUR=96;		# Bright cyan
RTL_LOG_MSG_VERBOSE_COLOUR=90;		# Dark grey
RTL_LOG_MSG_DEBUG_COLOUR=36;		# Dark cyan
RTL_TIMESTAMP_FMT="%Y/%m/%d %H:%M:%S";
RTLP_MKTEMP_FNAMES="";
UPDATE_IPTABLES_AF_LIST="4 6";
UPDATE_IPTABLES_PREREQS="
	date diff flock iptables-restore ip6tables-restore iptables-save
	ip6tables-save mktemp mv rm sed sleep";
UPDATE_IPTABLESP_INHIBIT_AST=0;
# }}}
# {{{ Public RTL subroutines
rtl_date() { command date "+${1:-${RTL_TIMESTAMP_FMT}}"; };
rtl_log_set_lvl() { RTL_LOG_LVL="${1}"; };

rtl_check_prereqs() {
	local _cmd="" _cmds_missing="" _rc=0; _status="";
	for _cmd in "${@}"; do
                if ! which "${_cmd}" >/dev/null 2>&1; then
                        _cmds_missing="${_cmds_missing:+${_cmds_missing} }${_cmd}";
                fi;
        done;
        if [ -n "${_cmds_missing}" ]; then
                _rc=1; _status="Error: missing prerequisite package(s): ${_cmds_missing}";
        fi;
        return "${_rc}";
};

rtl_flock_acquire() {
	local _fd="${1}" _conflict_exit_code="${2:-22}" _wait="${3:-3600}"
	while true; do
		if flock -E "${_conflict_exit_code}" -w "${_wait}" "${_fd}"; then
			break;
		elif [ "${?}" -eq "${_conflict_exit_code}" ]; then
			continue;
		else
			return "${?}";
		fi;
	done;
};

rtl_iptables_restore() {
	local _af="${1}" _fname="${2}";
	case "${_af}" in
	4)	iptables-restore < "${_fname}"; ;;
	6)	ip6tables-restore < "${_fname}"; ;;
	*)	return 1; ;;
	esac;
};

rtl_iptables_save() {
	local _af="${1}" _fname="${2}";
	case "${_af}" in
	4)	iptables-save > "${_fname}"; ;;
	6)	ip6tables-save > "${_fname}"; ;;
	*)	return 1; ;;
	esac;
};

rtl_ipset_flush() {
	ipset flush;
};

rtl_ipset_restore() {
	local _fname="${1}";
	ipset restore -exist < "${_fname}";
};

rtl_ipset_save() {
	local _fname="${1}";
	ipset save > "${_fname}";
};

rtl_lconcat() {
	local _list="${1}" _litem_new="${2}" _sep="${3:- }" IFS="${3:-${IFS}}";
	if [ -n "${_list}" ]; then
		printf "%s%s%s" "${_list}" "${_sep}" "${_litem_new}";
	else
		printf "%s" "${_litem_new}";
	fi;
};

rtl_lfilter() {
        local	_list="${1}" _filter="${2}" _sep="${3:- }" IFS="${3:-${IFS}}"	\
		_filterfl="" _litem="" _litem_filter="" _lnew="";
	if [ -z "${_filter}" ]; then
		printf "%s" "${_list}"; return 0;
	else for _litem in ${_list}; do
		_filterfl=0;
		for _litem_filter in ${_filter}; do
			if [ "${_litem_filter}" = "${_litem}" ]; then
				_filterfl=1; break;
			fi;
		done;
		if [ "${_filterfl:-0}" -eq 0 ]; then
			_lnew="${_lnew:+${_lnew}${_sep}}${_litem}";
		fi;
	done; fi;
	printf "%s" "${_lnew}";
};

rtl_lmatch() {
	local _list="${1}" _item="${2}" _sep="${3:- }";
	[ -n "$(rtl_lsearch "${_list}" "${_item}" "${_sep}")" ];
};

rtl_log_msg() {
	local _lvl="${1}" _fmt="${2}" _attr=""; shift 2;
	case "${RTL_LOG_LVL:-0}" in
	0)	rtl_lmatch "notice verbose debug" "${_lvl}" && return; ;;
	1)	rtl_lmatch "verbose debug" "${_lvl}" && return; ;;
	2)	rtl_lmatch "debug" "${_lvl}" && return; ;;
	3)	;;
	esac;
	case "${_lvl}" in
	fatal|fatalexit)	_attr="${RTL_LOG_MSG_FATAL_COLOUR}"; ;;
	warning)		_attr="${RTL_LOG_MSG_WARNING_COLOUR}"; ;;
	success)		_attr="${RTL_LOG_MSG_SUCCESS_COLOUR}"; ;;
	success_end)		_attr="${RTL_LOG_MSG_SUCCESS_END_COLOUR}"; ;;
	info)			_attr="${RTL_LOG_MSG_INFO_COLOUR}"; ;;
	info_end)		_attr="${RTL_LOG_MSG_INFO_END_COLOUR}"; ;;
	notice)			_attr="${RTL_LOG_MSG_NOTICE_COLOUR}"; ;;
	verbose)		_attr="${RTL_LOG_MSG_VERBOSE_COLOUR}"; ;;
	debug)			_attr="${RTL_LOG_MSG_DEBUG_COLOUR}"; ;;
	esac;
	rtl_log_printf "${_attr}" "==> %s ${_fmt}" "$(rtl_date)" "${@}";
	if [ "x${_lvl}" = "xfatalexit" ]; then
		exit 1;
	fi;
};

rtl_log_printf() {
	local _attr="${1}" _fmt="${2}"; shift 2; _msg="$(printf "${_fmt}" "${@}")";
	printf "\033[0m\033[%sm%s\033[0m\n" "${_attr}" "${_msg}";
};

rtl_lsearch() {
	local	_list="${1}" _filter="${2}" _sep="${3:- }" IFS="${3:-${IFS}}"	\
		_litem="" _litem_filter="" _lnew="";
	if [ -z "${_filter}" ]; then
		printf "%s" "${_list}"; return 0;
	else for _litem in ${_list}; do
		for _litem_filter in ${_filter}; do
			if [ "${_litem_filter}" = "${_litem}" ]; then
				_lnew="${_lnew:+${_lnew}${_sep}}${_litem}"; break;
			fi;
		done;
	done; fi;
	printf "%s" "${_lnew}";
};

rtl_mktemp() {
	RTL_MKTEMP_FNAME="";
	if ! RTL_MKTEMP_FNAME="$(mktemp)"; then
		return 1;
	else
		RTLP_MKTEMP_FNAMES="$(rtl_lconcat "${RTLP_MKTEMP_FNAMES:-}" "${RTL_MKTEMP_FNAME}")";
	fi;
};

rtl_mktemp_clear() {
	local _fname="";
	for _fname in ${RTLP_MKTEMP_FNAMES:-}; do
		rm -f "${_fname}" 2>/dev/null;
	done; RTLP_MKTEMP_FNAMES="";
};

rtl_mktemp_pop() {
	local _fname="${1}";
	RTLP_MKTEMP_FNAMES="$(rtl_lfilter "${RTLP_MKTEMP_FNAMES}" "${_fname}")";
};

rtl_prompt() {
	local _fmt="${1}" _choice=""; shift;
	printf "${_fmt}? (y|N) " "${@}";
	read -r _choice;
	case "${_choice}" in
	[yY])	_choice=1; ;;
	*)	_choice=0; ;;
	esac;
	return "${_choice}";
};

rtl_rc() {
	local _nflag="${1}" _cmd="${2}"; shift 2;
	case "${_nflag}" in
	1)	if [ "${#}" -gt 0 ]; then
			rtl_log_msg notice "Command line: %s %s" "${_cmd}" "${*}";
		else
			rtl_log_msg notice "Command line: %s" "${_cmd}";
		fi; ;;
	*)	"${_cmd}" "${@}";
	esac;
};
# }}}
# {{{ Public subroutines
update_iptables_apply() {
	local _af="${1}" _nflag="${2}" _set_fname="${3}" _set_fname_target="${4}" _rc=0; _status=""
	if ! rtl_rc "${_nflag}" rtl_iptables_restore "${_af}" "${_set_fname}"; then
		_rc=1; _status="Error: failed to apply IPv${_af} rule set from file \`${_set_fname}'.";
	elif ! rtl_rc "${_nflag}" mv "${_set_fname}" "${_set_fname_target}"; then
		_rc=1; _status="Error: failed to rename \`${_set_fname}' to \`${_set_fname_target}'.";
	fi; return "${_rc}";
};

update_iptables_ast() {
	if [ "${UPDATE_IPTABLESP_INHIBIT_AST:-0}" -ne 1 ]; then
		rtl_mktemp_clear;
	fi;
};

update_iptables_generate() {
	local _af="${1}" _nflag="${2}" _set_fname="${3}" _set_fname_target="${4}" _rc=0; _status=""
	if ! rtl_rc "${_nflag}" mv "${_set_fname}" "${_set_fname_target}"; then
		_rc=1; _status="Error: failed to rename \`${_set_fname}' to \`${_set_fname_target}'.";
	fi; return "${_rc}";
};

update_iptables_regenerate() {
	local _af="${1}" _tmp_fname="${2}" _chain_fname="" _chain_name="" _rc=0 _table_dname="" _table_name=""; _status="";
	(set +o errexit -o noglob -o nounset;
	if ! rtl_flock_acquire 3; then
		exit 1;
	else	trap "rm -f \"/etc/iptables/update_iptables.lock\" 2>/dev/null" EXIT HUP INT TERM USR1 USR2;
		rtl_log_msg success "Processing IPv%s rules..." "${_af}";
		for _table_dname in $(set +o noglob; echo "rules.v${_af}.d/"*); do
			_table_name="${_table_dname##*/}"; _table_name="${_table_name#*.}";
			rtl_log_msg info "Processing IPv%s \`%s' table..." "${_af}" "${_table_name}";
			if ! printf "*%s\n" "${_table_name}" >> "${_tmp_fname}"\
			|| ! sed -e '/^$/d' -e '/^#/d' "${_table_dname}/chain" >> "${_tmp_fname}"; then
				exit 2;
			else	for _chain_fname in $(set +o noglob; echo "${_table_dname}/"*); do
					if [ "x${_chain_fname##*/}" = "xchain" ]; then
						continue;
					else	_chain_name="${_chain_fname##*/}"; _chain_name="${_chain_name#*.}";
						if ! sed -ne '/^$/d' -e '/^#/d' -e 's/^/-A '"${_chain_name}"' /p' "${_chain_fname}" >> "${_tmp_fname}"; then
							exit 2;
						else
							rtl_log_msg verbose "Processed IPv%s \`%s' table \`%s' chain." "${_af}" "${_table_name}" "${_chain_name}";
						fi;
					fi;
				done;
				if ! printf "COMMIT\n" >> "${_tmp_fname}"; then
					exit 2;
				else
					rtl_log_msg info_end "Processed IPv%s \`%s' table." "${_af}" "${_table_name}";
				fi;
			fi;
		done;
		rtl_log_msg success_end "Processed IPv%s rules." "${_af}";
	fi;) 3<>"/etc/iptables/update_iptables.lock"; _rc="${?}";
	if [ "${_rc:-0}" -eq 0 ]\
	&& ! printf "\n# vim:filetype=conf\n" >> "${_tmp_fname}"; then
		_rc=2;
	fi;
	case "${_rc:-0}" in
	0)	UPDATE_IPTABLES_SET_FNAME="${_tmp_fname}"; ;;
	1)	_status="Error: failed to acquire lock \`/etc/iptables/update_iptables.lock'."; ;;
	2)	_status="Error: failed to append to temporary file \`${_tmp_fname}'."; ;;
	*)	_status="Error: unknown exit status from child process."; ;;
	esac;
	if [ "${_rc:-0}" -ne 0 ]; then
		rm -f "${_tmp_fname}" 2>/dev/null;
	fi; return "${_rc}";
};

update_iptables_testapply() {
	local	_af="${1}" _nflag="${2}" _set_fname="${3}" _set_fname_target="${4}"	\
		_rc=0 _rc_child=0 RTL_MKTEMP_FNAME=""; _status=""
	if ! rtl_mktemp; then
		_rc=1; _status="Error: failed to create temporary file.";
	elif ! rtl_rc "${_nflag}" rtl_iptables_save "${_af}" "${RTL_MKTEMP_FNAME}"; then
		_rc=1; _status="Error: failed to save original IPv${_af} rule set to file \`${RTL_MKTEMP_FNAME}'.";
	elif ! rtl_rc "${_nflag}" rtl_iptables_restore "${_af}" "${_set_fname}"; then
		_rc=1; _status="Error: failed to apply IPv${_af} rule set from file \`${_set_fname}'.";
	else	rtl_log_msg info "Restoring original ruleset in five (5) seconds.";
		rtl_log_msg info "Send an interrupt w/ <Control> C in order to keep and commit the new ruleset.";
		UPDATE_IPTABLESP_INHIBIT_AST=1; (trap "exit 10" INT; sleep 5; exit 0); _rc_child="${?}"; UPDATE_IPTABLESP_INHIBIT_AST=0;
		case "${_rc_child}" in
		10)	rtl_log_msg info "Committing new ruleset.";
			if ! rtl_rc "${_nflag}" mv "${_set_fname}" "${_set_fname_target}"; then
				_rc=1; _status="Error: failed to rename \`${_set_fname}' to \`${_set_fname_target}'.";
			fi; ;;
		*)	rtl_log_msg info "Restoring original rule set...";
			if ! rtl_rc "${_nflag}" rtl_iptables_restore "${_af}" "${RTL_MKTEMP_FNAME}"; then
				rtl_log_msg warning "Warning: failed to restore original IPv${_af} rule set from file \`${RTL_MKTEMP_FNAME}'.";
			else
				rtl_log_msg info_end "Restored original rule set.";
			fi;
			rm -f "${_set_fname}" 2>/dev/null; ;;
		esac;
	fi; rm -f "${RTL_MKTEMP_FNAME}" 2>/dev/null; return "${_rc}";
};

update_ipset_apply() {
	local _nflag="${1}" _set_fname_old="${2}" _set_fname_target="${3}" _rc=0; _status=""
	rtl_log_msg success "Applying IP set...";
	if ! rtl_rc "${_nflag}" rtl_ipset_flush; then
		_rc=1; _status="Error: failed to flush IP sets.";
	elif ! rtl_rc "${_nflag}" rtl_ipset_restore "${_set_fname_target}"; then
		_rc=1; _status="Error: failed to apply IP set from file \`${_set_fname_target}'.";
	else
		rtl_log_msg info_end "Applied IP set.";
	fi;
	return "${_rc}";
};

update_ipset_testapply() {
	local	_nflag="${1}" _set_fname_old="${2}" _set_fname_target="${3}"	\
		_rc=0 _rc_child=0 RTL_MKTEMP_FNAME=""; _status=""
	if ! rtl_mktemp; then
		_rc=1; _status="Error: failed to create temporary file.";
	elif ! rtl_rc "${_nflag}" rtl_ipset_save "${RTL_MKTEMP_FNAME}"; then
		_rc=1; _status="Error: failed to save original IP set to file \`${RTL_MKTEMP_FNAME}'.";
	elif ! rtl_rc "${_nflag}" rtl_ipset_flush; then
		_rc=1; _status="Error: failed to flush IP sets.";
	elif ! rtl_rc "${_nflag}" rtl_ipset_restore "${_set_fname_target}"; then
		_rc=1; _status="Error: failed to apply IP set from file \`${_set_fname_target}'.";
	else	rtl_log_msg info "Restoring original IP set in five (5) seconds.";
		rtl_log_msg info "Send an interrupt w/ <Control> C in order to keep and commit the new ruleset.";
		UPDATE_IPTABLESP_INHIBIT_AST=1; (trap "exit 10" INT; sleep 5; exit 0); _rc_child="${?}"; UPDATE_IPTABLESP_INHIBIT_AST=0;
		case "${_rc_child}" in
		10)	rtl_log_msg info "Committing new ruleset.";
			;;
		*)	rtl_log_msg info "Restoring original rule set...";
			if ! rtl_rc "${_nflag}" rtl_ipset_restore "${RTL_MKTEMP_FNAME}"; then
				rtl_log_msg warning "Warning: failed to restore original IP set from file \`${RTL_MKTEMP_FNAME}'.";
			else
				rtl_log_msg info_end "Restored original IP set.";
			fi;
			;;
		esac;
	fi; rm -f "${RTL_MKTEMP_FNAME}" 2>/dev/null; return "${_rc}";
};

update_iptables_usage() {
	printf "usage: %s [-a|-g|-t] [-c] [-h] [-n] [-v]\n" "${0}" >&2;
	printf "       -a ...: regenerate and apply ip{,6}tables(8) rule sets and ipset(8)\n" >&2;
	printf "       -g ...: regenerate ip{,6}tables(8) rule sets\n" >&2;
	printf "       -t ...: regenerate and test new ip{,6}tables(8) and ipset(8) w/ delayed prompt to commit\n" >&2;
	printf "       -c ...: ask for confirmation before processing new rule set and ipset(8)\n" >&2;
	printf "       -h ...: show this screen\n" >&2;
	printf "       -n ...: dry run (implies -v)\n" >&2;
	printf "       -v ...: increase verbosity\n" >&2;
};
# }}}

#
# Entry point
#
update_iptables() {
	local	_af="" _aflag=0 _cflag=0 _choice=0 _gflag=0 _nflag=0 _opt="" _rc=0\
		_set_fname="" _set_fname_old="" _status="" _tflag=0\
		RTL_MKTEMP_FNAME=""; UPDATE_IPTABLES_SET_FNAME="";
	while getopts acghntv _opt; do
	case "${_opt}" in
	a)	_aflag=1; ;;
	c)	_cflag=1; ;;
	g)	_gflag=1; ;;
	h)	update_iptables_usage; exit 0; ;;
	n)	_nflag=1; rtl_log_set_lvl 2; ;;
	t)	_tflag=1; ;;
	v)	rtl_log_set_lvl 2; ;;
	*)	update_iptables_usage; exit 1; ;;
	esac; done; shift $((${OPTIND}-1));
	if [ $((${_aflag:-0}+${_gflag:-0}+${_tflag:-0})) -eq 0 ]; then
		rtl_log_msg fatalexit "Error: one of -a, -g, and -t must be specified.";
	elif [ $((${_aflag:-0}+${_gflag:-0}+${_tflag:-0})) -gt 1 ]; then
		rtl_log_msg fatalexit "Error: only one of -a, -g, and -t may be specified.";
	elif ! rtl_check_prereqs ${UPDATE_IPTABLES_PREREQS}; then
		rtl_log_msg fatalexit "${_status}";
	elif ! cd "${0%/*}"; then
		rtl_log_msg fatalexit "Error: failed to change working directory to \`%s'." "${0%/*}";
	else	umask 027;
		trap update_iptables_ast EXIT HUP INT TERM USR1 USR2;
		for _af in ${UPDATE_IPTABLES_AF_LIST}; do
			if ! rtl_mktemp; then
				rtl_log_msg fatalexit "Error: failed to create temporary file.";
			else	_set_fname_old="${RTL_MKTEMP_FNAME}"; _set_fname_target="/etc/iptables/ipsets";
				rtl_ipset_save "${_set_fname_old}";
				if [ "${_cflag:-0}" -eq 1 ]\
				&& ! diff -u "${_set_fname_old}" "${_set_fname_target}"; then
					rtl_prompt "Commit to \`%s'" "${_set_fname_target}"; _choice="${?}";
				else
					_choice=1;
				fi;
				if [ "${_choice:-0}" -eq 1 ]; then
					if [ "${_aflag:-0}" -eq 1 ]; then
						update_ipset_apply "${_nflag}" "${_set_fname_old}" "${_set_fname_target}"; _rc="${?}";
					elif [ "${_tflag:-0}" -eq 1 ]; then
						update_ipset_testapply "${_nflag}" "${_set_fname_old}" "${_set_fname_target}"; _rc="${?}";
					fi;
					if [ "${_nflag:-0}" -eq 1 ]; then
						rm -f "${_set_fname_old}" 2>/dev/null;
					fi;
					if [ "${_rc:-0}" -ne 0 ]; then
						rtl_log_msg fatalexit "${_status}";
					fi;
				else
					rm -f "${_set_fname_old}" 2>/dev/null;
				fi;
			fi;

			if ! rtl_mktemp; then
				rtl_log_msg fatalexit "Error: failed to create temporary file.";
			elif ! update_iptables_regenerate "${_af}" "${RTL_MKTEMP_FNAME}"; then
				rtl_log_msg fatalexit "%s" "${_status}";
			else	_set_fname="${RTL_MKTEMP_FNAME}"; _set_fname_target="/etc/iptables/rules.v${_af}";
				if [ "${_cflag:-0}" -eq 1 ]\
				&& ! diff -u "${_set_fname_target}" "${_set_fname}"; then
					rtl_prompt "Commit to \`%s'" "${_set_fname_target}"; _choice="${?}";
				else
					_choice=1;
				fi;
				if [ "${_choice:-0}" -eq 1 ]; then
					if [ "${_aflag:-0}" -eq 1 ]; then
						update_iptables_apply "${_af}" "${_nflag}" "${_set_fname}" "${_set_fname_target}"; _rc="${?}";
					elif [ "${_tflag:-0}" -eq 1 ]; then
						update_iptables_testapply "${_af}" "${_nflag}" "${_set_fname}" "${_set_fname_target}"; _rc="${?}";
					elif [ "${_gflag:-0}" -eq 1 ]; then
						update_iptables_generate "${_af}" "${_nflag}" "${_set_fname}" "${_set_fname_target}"; _rc="${?}"
					fi;
					if [ "${_nflag:-0}" -eq 1 ]; then
						rm -f "${_set_fname}" 2>/dev/null;
					fi;
					if [ "${_rc:-0}" -ne 0 ]; then
						rtl_log_msg fatalexit "${_status}";
					fi;
				else
					rm -f "${_set_fname}" 2>/dev/null;
				fi;
			fi;
		done;
	fi;
};

set +o errexit -o noglob -o nounset; update_iptables "${@}";
