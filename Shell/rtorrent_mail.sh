#!/bin/sh

RTORRENT_BASE_URL="https://rtorrent";
RTORRENT_MAIL_TO="user";

rmp_encode_uri() {
	local _ruri="${1#\$}";
	eval "${_ruri}"=\"\$\(printf \"%s\" \"\$\{${_ruri}\}\" \| sed		\
		-e \'s,%,%25,g\'						\
		-e \'s,\(,%28,g\'						\
		-e \'s,\),%29,g\'						\
		-e \'s,\\[,%5b,g\'						\
		-e \'s,\\],%5d,g\'						\
		-e \'s,{,%7b,g\'						\
		-e \'s,},%7d,g\'						\
		-e \'s, ,%20,g\'\)\";
};

rmp_humanise() {
	local _rn="${1#\$}";

	if eval [ \"\${${_rn}}\" -ge 1073741824 ]; then
		eval "${_rn}"=\"$(eval printf \"scale=2\\n%u / 1073741824.0\\n\" \"\${${_rn}}\" | bc) GB\";
	elif eval [ \"\${${_rn}}\" -ge 1048576 ]; then
		eval "${_rn}"=\"$(eval printf \"scale=2\\n%u / 1048576.0\\n\" \"\${${_rn}}\" | bc) MB\";
	elif eval [ \"\${${_rn}}\" -ge 1024 ]; then
		eval "${_rn}"=\"$(eval printf \"scale=2\\n%u / 1024.0\\n\" \"\${${_rn}}\" | bc) KB\";
	else
		eval "${_rn}"=\"\${${_rn}} bytes\";
	fi;
};

rtorrent_mail() {
	local	_name="${1}" _base_filename="${2}" _base_path="${3}"		\
		_is_multi_file="${4}" _size_bytes="${5}" _size_files="${6}"	\
		_base_dname="" _fname="" _subject="" _torrent_file=""		\
		_torrent_file_list="" _url="" _IFS0="${IFS:- 	}";

	[ "${_is_multi_file}" = 1 ] || _is_multi_file="";
	_base_dname="${_base_path%/*}"; _base_dname="${_base_dname##*/}";
	_url="${RTORRENT_BASE_URL%/}/${_base_dname%/}/${_base_filename}${_is_multi_file:+/}";
	rmp_encode_uri \$_url;
	rmp_humanise \$_size_bytes || _size_bytes="(error)";
	if [ "${_is_multi_file:-0}" -eq 1 ]; then
		IFS="
";		for _fname in $(cd "${_base_path}" &&				\
				find . -type f | sort -V);
		do
			_torrent_file="${RTORRENT_BASE_URL%/}/${_base_dname%/}/${_base_filename%/}/${_fname#./}";
			rmp_encode_uri \$_torrent_file;
			_torrent_file_list="${_torrent_file_list:+${_torrent_file_list}
}${_torrent_file}";
		done; IFS="${_IFS0}";
	fi;

	/usr/bin/mail								\
		-s "Finished Torrent ${_name}"					\
		"${RTORRENT_MAIL_TO}"						\
<<-EOF
This email is to inform you that rtorrent has finished downloading ${_name}, which includes ${_size_files} files in ${_size_bytes} in total.
This torrent's files are available at:

${_url}
${_is_multi_file:+(this torrent has multiple files)}
${_torrent_file_list:+
This torrent's files are individually available at:
${_torrent_file_list}}
EOF
};

set +o errexit -o noglob -o nounset; rtorrent_mail "${@}";

# vim:ft=sh
