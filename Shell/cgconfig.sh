#!/bin/sh

CGROUP_PREFIX="/sys/fs/cgroup";

# {{{ Defaults (from <https://www.kernel.org/doc/Documentation/cgroup-v2.txt>)
#
# A read-write two value file which exists on non-root cgroups.
# The default is "max 100000".
#
# The maximum bandwidth limit.  It's in the following format::
#
#  $MAX $PERIOD
#
# which indicates that the group may consume upto $MAX in each
# $PERIOD duration.  "max" for $MAX indicates no limit.  If only
# one number is written, $MAX is updated.
#
: ${CGROUP_DEFAULT_CPU_MAX:="max 100000"};

#
# A read-write single value file which exists on non-root
# cgroups.  The default is "100".
#
# The weight in the range [1, 10000].
#
: ${CGROUP_DEFAULT_CPU_WEIGHT:="10000"};

#
# A read-write single value file which exists on non-root
# cgroups.  The default is "max".
# 
# Memory usage hard limit.  This is the final protection
# mechanism.  If a cgroup's memory usage reaches this limit and
# can't be reduced, the OOM killer is invoked in the cgroup.
# Under certain circumstances, the usage may go over the limit
# temporarily.
# 
# This is the ultimate protection mechanism.  As long as the
# high limit is used and monitored properly, this limit's
# utility is limited to providing the final safety net.
#
: ${CGROUP_DEFAULT_MEMORY_MAX:="$((512 * 1024 * 1024))"};

#
# A read-write single value file which exists on non-root
# cgroups.  The default is "max".
#
# Hard limit of number of processes.
#
: ${CGROUP_DEFAULT_PIDS_MAX:="64"};
# }}}
# {{{ RTL functions
rtl_cgroup_create_subdir() {
	local _vflag="${1}" _cgroup="${2}" _mode="${3}" _owner="${4}";
	if [ "${_vflag:-0}" -eq 1 ]; then
		rtl_log_verbose "Creating ${CGROUP_PREFIX}/${_cgroup}.";
	fi;
	if ! [ -d "${CGROUP_PREFIX}/${_cgroup}" ]\
	&& ! mkdir "${CGROUP_PREFIX}/${_cgroup}"; then
		rtl_log_error "failed to create ${CGROUP_PREFIX}/${_cgroup}."; return 1;
	elif ! chmod "${_mode}" "${CGROUP_PREFIX}/${_cgroup}"; then
		rtl_log_error "failed to chmod ${CGROUP_PREFIX}/${_cgroup} to ${_mode}."; return 1;
	elif ! chown "${_owner}" "${CGROUP_PREFIX}/${_cgroup}"; then
		rtl_log_error "failed to chown ${CGROUP_PREFIX}/${_cgroup} to ${_owner}."; return 1;
	elif ! chown "${_owner}" "${CGROUP_PREFIX}/${_cgroup}/cgroup.procs"; then
		rtl_log_error "failed to chown ${CGROUP_PREFIX}/${_cgroup}/cgroup.procs to ${_owner}."; return 1;
	else
		return 0;
	fi;
};

rtl_cgroup_write_file() {
	local _vflag="${1}" _cgroup="${2}" _fname="${3}" _vname="${4}";
	if [ "${_vflag:-0}" -eq 1 ]; then
		rtl_log_verbose "Writing \`%s' to ${CGROUP_PREFIX}/${_cgroup}/${_fname}." "${_vname}";
	fi;
	if ! printf "${_vname}\n" >| "${CGROUP_PREFIX}/${_cgroup}/${_fname}"; then
		rtl_log_warning "failed to write \`%s' to ${CGROUP_PREFIX}/${_cgroup}/${_fname}." "${_vname}"; return 1;
	else
		return 0;
	fi;
};

rtl_get_users() {
	local _gname="${1}" _group_entry="" _group_id=0 _users="" _users_passwd="";
	if ! _group_entry="$(getent group "${_gname}")"; then
		rtl_log_error "invalid or unknown group \`%s'." "${_gname}"; return 1;
	elif ! _group_id="$(printf "%s\n" "${_group_entry}" | awk -F: '{print $3}')"; then
		rtl_log_error "failed to obtain GID from group \`%s'." "${_gname}"; return 2;
	elif ! _users="$(printf "%s\n" "${_group_entry}" | awk -F: '{print $4}' | sed 's/,/\n/g')"; then
		rtl_log_error "failed to obtain secondary group users from group \`%s'." "${_gname}"; return 3;
	elif ! _users_passwd="$(awk -F: '$4 == '"${_group_id}"' {print $1}' /etc/passwd | paste -s -d" ")"; then
		rtl_log_error "failed to obtain primary group users from group \`%s'." "${_gname}"; return 4;
	else	_users="$(rtl_uniq $(rtl_lconcat "${_users}" "${_users_passwd}"))";
		echo "${_users}"; return 0;
	fi;
};

rtl_get_var_unsafe() {
	local _vname="";
	if [ "x${1}" = "x-u" ]; then
		shift; _vname="$(rtl_toupper "${1}")";
	else
		_vname="${1}";
	fi;
	eval echo \${${_vname}} 2>/dev/null;
};

rtl_lconcat() {
	local _list="${1}" _litem_new="${2}" _sep="${3:- }" IFS="${3:-${IFS:- }}";
	if [ -n "${_list}" ]; then
		printf "%s%s%s" "${_list}" "${_sep}" "${_litem_new}";
	else
		printf "%s" "${_litem_new}";
	fi;
};

rtl_log_error() {
	local _fmt="${1}" _ts="$(date +"%d-%^b-%Y %H:%M:%S" 2>/dev/null)"; shift;
	printf "[91m%s Error: ${_fmt}[0m\n" "${_ts}" "${@}" >&2;
};

rtl_log_warning() {
	local _fmt="${1}" _ts="$(date +"%d-%^b-%Y %H:%M:%S" 2>/dev/null)"; shift;
	printf "[31m%s Warning: ${_fmt}[0m\n" "${_ts}" "${@}" >&2;
};

rtl_log_verbose() {
	local _fmt="${1}" _ts="$(date +"%d-%^b-%Y %H:%M:%S" 2>/dev/null)"; shift;
	printf "[96m%s ${_fmt}[0m\n" "${_ts}" "${@}" >&2;
};

rtl_toupper() {
	local _s="${1}" _s_new="";
	while [ -n "${_s}" ]; do
	case "${_s}" in
	a*)     _s_new="${_s_new:+${_s_new}}A"; _s="${_s#a}"; ;;
	b*)     _s_new="${_s_new:+${_s_new}}B"; _s="${_s#b}"; ;;
	c*)     _s_new="${_s_new:+${_s_new}}C"; _s="${_s#c}"; ;;
	d*)     _s_new="${_s_new:+${_s_new}}D"; _s="${_s#d}"; ;;
	e*)     _s_new="${_s_new:+${_s_new}}E"; _s="${_s#e}"; ;;
	f*)     _s_new="${_s_new:+${_s_new}}F"; _s="${_s#f}"; ;;
	g*)     _s_new="${_s_new:+${_s_new}}G"; _s="${_s#g}"; ;;
	h*)     _s_new="${_s_new:+${_s_new}}H"; _s="${_s#h}"; ;;
	i*)     _s_new="${_s_new:+${_s_new}}I"; _s="${_s#i}"; ;;
	j*)     _s_new="${_s_new:+${_s_new}}J"; _s="${_s#j}"; ;;
	k*)     _s_new="${_s_new:+${_s_new}}K"; _s="${_s#k}"; ;;
	l*)     _s_new="${_s_new:+${_s_new}}L"; _s="${_s#l}"; ;;
	m*)     _s_new="${_s_new:+${_s_new}}M"; _s="${_s#m}"; ;;
	n*)     _s_new="${_s_new:+${_s_new}}N"; _s="${_s#n}"; ;;
	o*)     _s_new="${_s_new:+${_s_new}}O"; _s="${_s#o}"; ;;
	p*)     _s_new="${_s_new:+${_s_new}}P"; _s="${_s#p}"; ;;
	q*)     _s_new="${_s_new:+${_s_new}}Q"; _s="${_s#q}"; ;;
	r*)     _s_new="${_s_new:+${_s_new}}R"; _s="${_s#r}"; ;;
	s*)     _s_new="${_s_new:+${_s_new}}S"; _s="${_s#s}"; ;;
	t*)     _s_new="${_s_new:+${_s_new}}T"; _s="${_s#t}"; ;;
	u*)     _s_new="${_s_new:+${_s_new}}U"; _s="${_s#u}"; ;;
	v*)     _s_new="${_s_new:+${_s_new}}V"; _s="${_s#v}"; ;;
	w*)     _s_new="${_s_new:+${_s_new}}W"; _s="${_s#w}"; ;;
	x*)     _s_new="${_s_new:+${_s_new}}X"; _s="${_s#x}"; ;;
	y*)     _s_new="${_s_new:+${_s_new}}Y"; _s="${_s#y}"; ;;
	z*)     _s_new="${_s_new:+${_s_new}}Z"; _s="${_s#z}"; ;;
	[!abcdefghijklmnopqrstuvwxyz]*)
		_s_new="${_s_new:+${_s_new}}${_s%%[abcdefghijklmnopqrstuvwxyz]*}";
		while [ "${_s#[!abcdefghijklmnopqrstuvwxyz]}" != "${_s}" ]; do
			_s="${_s#[!abcdefghijklmnopqrstuvwxyz]}";
		done; ;;
	esac; done;
	printf "%s" "${_s_new}";
};

rtl_uniq() {
	if [ "${#}" -gt 0 ]; then
		printf "%s" "${*}" | sed 's/ /\n/g' | awk '!x[$0]++' | paste -s -d" ";
	fi;
};
# }}}

: ${CGROUP_USERS_GROUP:="users"};

cgconfigp_get_var() {
	local _uname="${1}" _vname="${2}" _vval="";
	if _vval="$(rtl_get_var_unsafe -u "CGROUP_${_uname}_${_vname}")"\
	&& [ -n "${_vval}" ]; then
		printf "%s" "${_vval}";
	elif _vval="$(rtl_get_var_unsafe -u "CGROUP_DEFAULT_${_vname}")"\
	&&   [ -n "${_vval}" ]; then
		printf "%s" "${_vval}";
	fi;
};

cgconfig_usage() {
	printf "usage: %s [-h] [-v]\n" "${1}";
};

cgconfig() {
	local _opt="" _uname="" _unames="" _vflag=0 _vval="";
	while getopts hv _opt; do
	case "${_opt}" in
	h)	cgconfig_usage "${0}"; exit 0; ;;
	v)	_vflag=1; ;;
	*)	cgconfig_usage "${0}"; exit 1; ;;
	esac;
	done; shift $((${OPTIND}-1));
	if [ -e "/etc/default/cgconfig" ]; then
		if ! . "/etc/default/cgconfig"; then
			rtl_log_error "failed to source \`/etc/default/cgconfig'."; exit 2;
		fi;
	fi;
	if ! rtl_cgroup_create_subdir "${_vflag}" "users" 0755 "root"; then
		exit 3;
	elif ! rtl_cgroup_write_file "${_vflag:-0}" "" "cgroup.subtree_control" "+cpu +memory +pids"; then
		exit 4;
	elif ! rtl_cgroup_write_file "${_vflag:-0}" "users" "cgroup.subtree_control" "+cpu +memory +pids"; then
		exit 5;
	elif ! rtl_cgroup_write_file "${_vflag:-0}" "users" "cpu.weight" "10000"; then
		exit 6;
	elif ! _unames="$(rtl_get_users "${CGROUP_USERS_GROUP}")"; then
		exit 7;
	else	for _uname in ${_unames}; do
			if rtl_cgroup_create_subdir "${_vflag}" "users/${_uname}" 0750 "${_uname}"; then
				if _vval="$(cgconfigp_get_var "${_uname}" "CPU_MAX")"; then
					rtl_cgroup_write_file "${_vflag:-0}" "users/${_uname}" "cpu.max" "${_vval}";
				fi;
				if _vval="$(cgconfigp_get_var "${_uname}" "CPU_WEIGHT")"; then
					rtl_cgroup_write_file "${_vflag:-0}" "users/${_uname}" "cpu.weight" "${_vval}";
				fi;
				if _vval="$(cgconfigp_get_var "${_uname}" "MEMORY_MAX")"; then
					rtl_cgroup_write_file "${_vflag:-0}" "users/${_uname}" "memory.max" "${_vval}";
				fi;
				if _vval="$(cgconfigp_get_var "${_uname}" "PIDS_MAX")"; then
					rtl_cgroup_write_file "${_vflag:-0}" "users/${_uname}" "pids.max" "${_vval}";
				fi;
			fi;
		done;
	fi;
};

set +o errexit -o noglob -o nounset; cgconfig "${@}";
