dnl The OpenBSD VMM driver
dnl
dnl Copyright (C) 2016 Sergey Bronnikov
dnl
dnl This library is free software; you can redistribute it and/or
dnl modify it under the terms of the GNU Lesser General Public
dnl License as published by the Free Software Foundation; either
dnl version 2.1 of the License, or (at your option) any later version.
dnl
dnl This library is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
dnl Lesser General Public License for more details.
dnl
dnl You should have received a copy of the GNU Lesser General Public
dnl License along with this library.  If not, see
dnl <http://www.gnu.org/licenses/>.
dnl

AC_DEFUN([LIBVIRT_DRIVER_CHECK_OPENBSD_VMM],[
    AC_ARG_WITH([openbsd_vmm],
      [AS_HELP_STRING([--with-openbsd-vmm],
        [add OpenBSD VMM support @<:@default=check@:>@])])
    m4_divert_text([DEFAULTS], [with_openbsd_vmm=check])

    if test "$with_openbsd_vmm" != "no"; then
        AC_PATH_PROG([VMD], [vmd], [], [$PATH:/usr/sbin])
        AC_PATH_PROG([VMCTL], [vmctl], [], [$PATH:/usr/sbin])

        if test -z "$VMD" || test -z "$VMCTL" || test "$with_openbsd" = "no"; then
            if test "$with_openbsd_vmm" = "check"; then
                with_openbsd_vmm="no"
            else
                AC_MSG_ERROR([The OpenBSD VMM driver cannot be enabled])
            fi
        else
            with_openbsd_vmm="yes"
        fi
    fi

    if test "$with_openbsd_vmm" = "yes"; then
        AC_DEFINE_UNQUOTED([WITH_OPENBSD_VMM], 1, [whether OpenBSD VMM driver is enabled])
        AC_DEFINE_UNQUOTED([VMD], ["$VMD"],
                           [Location of the vmd tool])
        AC_DEFINE_UNQUOTED([VMCTL], ["$VMCTL"],
                           [Location of the vmctl tool])
    fi
    AM_CONDITIONAL([WITH_OPENBSD_VMM], [test "$with_openbsd_vmm" = "yes"])
])

AC_DEFUN([LIBVIRT_DRIVER_RESULT_OPENBSD_VMM],[
    AC_MSG_NOTICE([OpenBSD VMM: $with_openbsd_vmm])
])
