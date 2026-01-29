#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#define CYGWIN_PATH_WINDOWS	"C:\\Cygwin64\\bin"
#define VSCODE_PATH_WINDOWS	"C:\\Program Files\\VSCodium\\VSCodium.exe"

static void envcatf(char **buf, size_t *buf_len, size_t *buf_size, const char *restrict fmt, ...);
static int err_windows(int eval, const char *fmt, ...);
static int execvp_windows(const char *argv0, int argc, char **argv);
static void strcatf(char **buf, size_t *buf_size, const char *restrict fmt, ...);

static void envcatf(char **buf, size_t *buf_len, size_t *buf_size, const char *restrict fmt, ...)
{
	va_list ap;
	char *buf_new;
	size_t buf_new_size;
	int nprinted;

	va_start(ap, fmt);
	nprinted = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);
	if (nprinted < 0) {
		fprintf(stderr, "vsnprintf: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	} else if (nprinted > 0) {
		if ((buf_new_size = *buf_len + nprinted + 2) >= *buf_size) {
			if (!(buf_new = realloc(*buf, buf_new_size))) {
				fprintf(stderr, "realloc: %s\n", strerror(errno));
				exit(EXIT_FAILURE);
			} else
				*buf = buf_new, *buf_size = buf_new_size;
		}
		va_start(ap, fmt);
		nprinted = vsnprintf(*buf + *buf_len, *buf_size - *buf_len, fmt, ap);
		va_end(ap);
		if (nprinted < 0) {
			fprintf(stderr, "snprintf: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		} else
			(*buf)[*buf_len + nprinted] = '\0', *buf_len += nprinted + 1;
	}
}

static int err_windows(int eval, const char *fmt, ...)
{
	va_list ap;
	char *errorMessage = NULL;

	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL,
				  GetLastError(), 0, (LPTSTR)&errorMessage, 0, NULL);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, ": %s", errorMessage ? errorMessage : "(error retrieving error message)\n");
	return eval;
}

static int execvp_windows(const char *argv0, int argc, char **argv)
{
	char *CommandLine = NULL, *Environment = NULL;
	size_t CommandLine_size = 0, Environment_len = 0, Environment_size = 0;
	int path_val_begin, path_val_end;
	PROCESS_INFORMATION ProcessInformation;
	STARTUPINFO StartupInfo;

	(void)Environment_size;
	strcatf(&CommandLine, &CommandLine_size, "\"%s\"", argv0);
	for (int narg = 1; narg < argc; narg++)
		strcatf(&CommandLine, &CommandLine_size, " \"%s\"", argv[narg]);
	for (char *p = GetEnvironmentStrings(), *q = NULL; p[0] && p[1]; p = q) {
		if (!(q = strchr(p, '\0')))
			break;
		else {
			path_val_begin = path_val_end = -1, q++;
			sscanf(p, "%*[Pp]%*[Aa]%*[Tt]%*[Hh]=%n%*s%n", &path_val_begin, &path_val_end);
			if ((path_val_begin != -1) && (path_val_end != -1))
				envcatf(&Environment, &Environment_len, &Environment_size,
					"PATH=%*s;%s", (path_val_end - path_val_begin), &p[path_val_begin], CYGWIN_PATH_WINDOWS);
			else
				envcatf(&Environment, &Environment_len, &Environment_size, "%s", p);
		}
	}
	envcatf(&Environment, &Environment_len, &Environment_size, "");
	memset(&StartupInfo, 0, sizeof(StartupInfo));
	StartupInfo.cb = sizeof(StartupInfo);
	if (!CreateProcess(argv0, CommandLine, NULL, NULL, TRUE, 0,
					   Environment, NULL, &StartupInfo, &ProcessInformation))
		return err_windows(EXIT_FAILURE, "CreateProcess");
	else
		return EXIT_SUCCESS;
}

static void strcatf(char **buf, size_t *buf_size, const char *restrict fmt, ...)
{
	va_list ap;
	size_t buf_len;
	char *buf_new;
	size_t buf_new_size;
	int nprinted;

	va_start(ap, fmt);
	nprinted = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);
	if (nprinted < 0) {
		fprintf(stderr, "vsnprintf: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	} else if (nprinted > 0) {
		buf_len = *buf ? strlen(*buf) : 0;
		if ((buf_new_size = buf_len + nprinted + 1) >= *buf_size) {
			if (!(buf_new = realloc(*buf, buf_new_size))) {
				fprintf(stderr, "realloc: %s\n", strerror(errno));
				exit(EXIT_FAILURE);
			} else
				*buf = buf_new, *buf_size = buf_new_size;
		}
		va_start(ap, fmt);
		nprinted = vsnprintf(*buf + buf_len, *buf_size - buf_len, fmt, ap);
		va_end(ap);
		if (nprinted < 0) {
			fprintf(stderr, "snprintf: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
}

int main(int argc, char **argv)
{
	FreeConsole();
	return execvp_windows(VSCODE_PATH_WINDOWS, argc, argv);
}
