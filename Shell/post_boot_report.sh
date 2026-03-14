#!/bin/sh

SYSTEMD_SERVICES="
";

EMAILEMAIL_TMP_FNAME="";

post_boot_report() {
	local _service="";

	EMAIL_TMP_FNAME="$(mktemp)" || return 1;
	trap 'rm -f "${EMAIL_TMP_FNAME}" 2>/dev/null' ALRM EXIT HUP INT TERM USR1 USR2;

	(
	printf "System information:\n";
	uname -a;
	printf "\n\n";

	printf "Logged on users:\n";
	who;
	printf "\n\n";

	printf "Filesystem state:\n";
	df -h;
	printf "\n\n";

	printf "Networking state:\n";
	ip link;
	ip addr;
	printf "\n\n";

	printf "Failed systemd units:\n";
	if [ "$(systemctl list-units -q --no-pager --state=failed 2>/dev/null | wc -l)" -eq 0 ]; then
		printf "(none)\n";
	else
		systemctl list-units -q --no-pager --state=failed;
	fi;
	printf "\n\n";

	printf "Systemd services state (short):\n";
	systemctl list-units -q --no-pager ${SYSTEMD_SERVICES};
	printf "\n\n";

	printf "Systemd services state (long):\n";
	printf "\n";
	for _service in ${SYSTEMD_SERVICES}; do
		systemctl status --no-pager "${_service}";
		printf "\n";
	done;
	printf "\n\n";

	printf "Iptables state:\n";
	iptables -vnL;
	printf "\n\n";

	printf "Full process list:\n";
	ps alx | grep -v "\[[^]]*\]\$";
	) >"${EMAIL_TMP_FNAME}" 2>&1;

	mail -s "Post-boot report for $(hostname -f)" root < "${EMAIL_TMP_FNAME}";
	return 0;
};

set +o errexit -o noglob -o nounset; post_boot_report "${@}";
