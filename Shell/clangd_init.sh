#!/bin/sh

clangd_init() {
	local	_clang="$(which clang)" _clang_cxx="$(which clang++)" _pwd="${PWD}"\
		_cflags="-I." _compiler="" _dname="" _fname="" _tmp_fname="" IFS;
	if ! _tmp_fname="$(mktemp)"; then
		return 1;
	else	trap "rm -f \"${_tmp_fname}\" >/dev/null 2>&1" ALRM EXIT HUP INT TERM USR1 USR2; IFS="
";		for _fname in $(find "${_pwd}" -type f \( -name *.c -or -name \*.cc -or -name \*.cxx \)); do
			_dname="${_fname%/*}"; _fname="${_fname##*/}";
			case "${_fname##*.}" in
			c)	_compiler="${_clang}"; ;;
			cc|cxx)	_compiler="${_clang_cxx}"; ;;
			*)	printf "Unknown file type \`.%s', ignoring \`%s'.\n" "${_fname##*.}" "${_fname}" >&2;
				continue; ;;
			esac;
			printf '  { "directory": "%s", "command": "%s %s -c -o %s.o %s", "file": "%s" },\n'\
				"${_dname}" "${_compiler}" "${_cflags}" "${_fname%.c}" "${_fname}" "${_fname}";
		done >>"${_tmp_fname}";
		printf '1i\n[\n.\n$s/,$//\n$a\n]\n.\nwq\n' | ed -s "${_tmp_fname}";
		mv "${_tmp_fname}" compile_commands.json;
		trap - ALRM EXIT HUP INT TERM USR1 USR2;
	fi;
};

set +o errexit -o noglob -o nounset; clangd_init "${@}";
