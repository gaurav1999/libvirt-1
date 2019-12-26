dnl The OpenBSD VMM driver
dnl
dnl Copyright (C) 2019 Sergey Bronnikov
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

AC_DEFUN([LIBVIRT_DRIVER_ARG_VMM], [
  LIBVIRT_ARG_WITH_FEATURE([VMM], [OpenBSD VMM], [check])
])

AC_DEFUN([LIBVIRT_DRIVER_CHECK_VMM], [
  OPENBSD_REQUIRED="5.9"
  OS_NAME=`uname -s`

  if test "$OS_NAME" = "OpenBSD"; then
	with_openbsd="yes"
  else
	with_openbsd="no"
  fi

  if test "$with_vmm" != "no"; then
      if test "$with_openbsd" = "no"; then
          if test "$with_vmm" = "check"; then
              with_vmm="no"
          else
              AC_MSG_ERROR([The OpenBSD VMM driver cannot be enabled])
          fi
      else
          with_vmm="yes"
      fi
  fi

  if test "$with_vmm" = "check"; then
    with_vmm=yes
  fi

  if test "$with_vmm" = "yes" ; then
    AC_DEFINE_UNQUOTED([WITH_VMM], 1, [whether VMM driver is enabled])
  fi
  AM_CONDITIONAL([WITH_VMM], [test "$with_vmm" = "yes"])
])

AC_DEFUN([LIBVIRT_DRIVER_RESULT_VMM], [
  LIBVIRT_RESULT([VMM], [$with_vmm])
])
