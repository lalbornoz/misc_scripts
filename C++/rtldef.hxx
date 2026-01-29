/*
 * rtldef.hxx
 * Copyright 2019 Lucía Andrea Illanes Albornoz <lucia@luciaillanes.de>
 */

#ifndef _RTLDEF_HXX_
#define _RTLDEF_HXX_

#include <string>
#include <utility>
#include <vector>
#include <windows.h>

namespace Rtl {

/*
 * Public Either<T1, T2> definitions
 */

template <typename T1, typename T2>
struct Either
{
    T1 left; T2 right;

    Either(T1 left, T2 right) : left {left}, right {right} {};
    constexpr operator T1() const { return this->left; };
    constexpr operator T2() const { return this->right; };
};

/*
 * Public {STATUS,Status<T>} definitions
 */

typedef uint64_t STATUS_COND;

typedef enum tagSTATUS_FACILITY
{
    SFACILITY_NONE      = 0,
    SFACILITY_POSIX     = 1,
    SFACILITY_WINDOWS   = 2,
} STATUS_FACILITY;

typedef enum tagSTATUS_SEVERITY
{
    SSEVERITY_WARNING   = 0,
    SSEVERITY_SUCCESS   = 1,
    SSEVERITY_ERROR     = 2,
    SSEVERITY_INFO      = 3,
    SSEVERITY_SEVERE    = 4,
} STATUS_SEVERITY;

typedef struct tagStatus
{
    STATUS_COND cond;
    STATUS_FACILITY facility;
    STATUS_SEVERITY severity;

    tagStatus() : cond(0), facility(SFACILITY_NONE), severity(SSEVERITY_SUCCESS) {};
    tagStatus(STATUS_SEVERITY severity) : cond(0), facility(SFACILITY_NONE), severity(severity) {};
    tagStatus(STATUS_FACILITY facility, STATUS_SEVERITY severity);
    tagStatus(STATUS_COND cond, STATUS_FACILITY facility, STATUS_SEVERITY severity) : cond(cond), facility(facility), severity(severity) {};
    constexpr explicit operator bool() const { return (this->severity & 1); };
} STATUS;

template <typename T>
struct Status : public Either<STATUS&, T>
{
    Status(STATUS& left, T right) : Either<STATUS&, T>(left, right) {};
    constexpr explicit operator bool() const { return (bool)this->left; }
    constexpr operator STATUS() const { return this->left; }

    template<typename Tr>
    constexpr Status<T>& operator=(const Status<Tr>& rhs)
    {
        return this->left = rhs.left, this->right = rhs.right, *this;
    }
};

template <typename T>
constexpr Status<T&> tie(STATUS& left, T& right)
{
    return Status<T&>(left, right);
}

/*
 * Public type definitions
 */

class Fd
{
private:
    int fd;

public:
    Fd(int fd=-1) : fd (fd) {};
    ~Fd();
    constexpr explicit operator bool() const { return (this->fd != -1); };
    constexpr operator int() const { return this->fd; };
};

class Handle
{
private:
    HANDLE handle;

public:
    Handle(HANDLE handle=INVALID_HANDLE_VALUE) : handle (handle) {};
    ~Handle() { if (this->handle != INVALID_HANDLE_VALUE) CloseHandle(this->handle); };
    explicit operator bool() const { return (this->handle != INVALID_HANDLE_VALUE); };
    constexpr operator HANDLE() const { return this->handle; };
    constexpr HANDLE* operator&() const { return (HANDLE *)&this->handle; };
};

class Pid
{
private:
    int pid;

public:
    Pid(int pid=-1) : pid (pid) {};
    ~Pid();
    constexpr explicit operator bool() const { return (this->pid != -1); };
    constexpr operator int() const { return this->pid; };
};

}
#endif /* !_RTLDEF_HXX_ */

/*
 * vim:expandtab sw=4 ts=4
 */
