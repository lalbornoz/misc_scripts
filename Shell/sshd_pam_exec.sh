#!/bin/sh

PAM_IGNORE=25;
PAM_SERVICE_ERR=3;
PAM_SUCCESS=0;
PAM_SYSTEM_ERR=4;

sshd_pam_exec() {
	local _cgroup="users/${PAM_USER}" _rc="${PAM_SUCCESS}" _sshd_pid="";
	trap '' HUP INT QUIT TERM USR1 USR2;
	if [ "${PAM_USER}" = "root" ]\
	|| [ "${PAM_USER}" = "toor" ]; then
		_rc=0;
	elif ! _sshd_pid="$(ps -ho ppid -p "${$}" 2>/dev/null)"; then
		_rc=1;
	else	_sshd_pid="${_sshd_pid##[ ]}";
		if [ -d "/sys/fs/cgroup/${_cgroup}" ]; then
			printf "[90mMoving process %s to cgroup \`%s'.[0m\n" "${_sshd_pid}" "${_cgroup}" >&2;
			printf "${_sshd_pid}" >| "/sys/fs/cgroup/${_cgroup}/cgroup.procs" || _rc="${PAM_SYSTEM_ERR}";
		fi;
	fi;
	return "${_rc:-0}";
};

set +o errexit -o noglob -o nounset; sshd_pam_exec "${@}";
