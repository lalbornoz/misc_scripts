/*
 * subr-rtl.cxx
 * Copyright 2019 Lucía Andrea Illanes Albornoz <lucia@luciaillanes.de>
 */

#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <windows.h>
#include "rtldef.hxx"

namespace Rtl {

/*
 * Public class method declarations
 */

tagStatus::tagStatus(STATUS_FACILITY facility, STATUS_SEVERITY severity)
{
    if ((severity == SSEVERITY_ERROR) && (facility == SFACILITY_POSIX))
        this->cond = errno;
    else if ((severity == SSEVERITY_ERROR) && (facility == SFACILITY_WINDOWS))
        this->cond = GetLastError();
    this->facility = facility, this->severity = severity;
}

Fd::~Fd()
{
    if (this->fd != -1)
        ::close(this->fd);
}

Pid::~Pid()
{
    if (this->pid != -1)
        kill(this->pid, SIGTERM);
}

}
/*
 * vim:expandtab sw=4 ts=4
 */
