dnl -*- mode: shell-script; -*-
dnl the usual 'configure.in' boilerplate
dnl

AC_INIT([ipsumdump], [1.86])
AC_PREREQ(2.60)
AC_CONFIG_HEADERS([config.h:config.h.in], [echo > stamp-h])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([src/Makefile])
AC_SUBST([ac_configure_args])

IPSUMDUMP_VERSION=1.86
AC_DEFINE_UNQUOTED([IPSUMDUMP_VERSION], ["$IPSUMDUMP_VERSION"], [Version of ipsumdump binary.])
AC_SUBST(IPSUMDUMP_VERSION)

AC_DEFUN([AC_LIBCLICK_VERSION], [2.1])
LIBCLICK_VERSION=AC_LIBCLICK_VERSION
AC_SUBST(LIBCLICK_VERSION)
AC_CONFIG_AUX_DIR([libclick-]AC_LIBCLICK_VERSION)

CLICK_INIT('$(top_srcdir)/libclick-'AC_LIBCLICK_VERSION)

AC_ARG_ENABLE(ip6, [  --disable-ip6           disable IPv6 support], , [enable_ip6=yes; ac_configure_args="$ac_configure_args '--enable-ip6'"])
AC_ARG_ENABLE(nanotimestamp, [  --disable-nanotimestamp disable nanosecond timestamps], , [enable_nanotimestamp=yes; ac_configure_args="$ac_configure_args '--enable-nanotimestamp'"])


dnl
dnl locate Click install directory
dnl

AC_ARG_WITH(click, [  --with-click[[=DIR]]      Click is installed under DIR],
  [clickprefix=$withval; if test -z "$withval" -o "$withval" = yes; then clickprefix=$prefix; fi],
  clickprefix=NONE)

dnl Preset $prefix and $exec_prefix.
test "x$prefix" = xNONE && prefix=$ac_default_prefix
test "x$exec_prefix" = xNONE && exec_prefix='${prefix}'

if test "$clickprefix" = NONE; then
    LIBCLICK_TARGET=libclick-AC_LIBCLICK_VERSION
    CLICK_BUILDTOOL='$(top_builddir)/'"$LIBCLICK_TARGET"'/click-buildtool'
    CLICKINCLUDES='-I$(top_builddir)/'"$LIBCLICK_TARGET"'/include -I$(top_srcdir)/'"$LIBCLICK_TARGET"'/include'
    CLICKLIB='$(top_builddir)/'"$LIBCLICK_TARGET"'/libsrc/libclick.a'
    CLICKLIBFILE=$CLICKLIB
    AC_CONFIG_SUBDIRS(libclick-AC_LIBCLICK_VERSION)
else
    LIBCLICK_TARGET=
    CLICK_BUILDTOOL="${clickprefix}/bin/click-buildtool"
    CLICKINCLUDES=
    CLICKLIB="-L${clickprefix}/lib -lclick"
    CLICKLIBFILE=
fi

AC_SUBST(LIBCLICK_TARGET)
AC_SUBST(CLICK_BUILDTOOL)
AC_SUBST(CLICKINCLUDES)
AC_SUBST(CLICKLIB)
AC_SUBST(CLICKLIBFILE)


dnl
dnl Are Click sources available?
dnl

AC_ARG_WITH(click-build, [  --with-click-build=DIR  DIR is Click build directory],
  [clickbuilddir=$withval], clickbuilddir=NONE)

if test "x$clickbuilddir" != x -a "x$clickbuilddir" != xNONE; then
    if test ! -r $clickbuilddir/config.status; then
	AC_MSG_ERROR([$clickbuilddir is not a Click build directory!])
    fi
    clicksrcdir=`grep '^top_srcdir' $clickbuilddir/Makefile | sed 's/top_srcdir = //'`
    if echo "$clicksrcdir" | grep '^\.' >/dev/null 2>&1; then
	clicksrcdir="$clickbuilddir/$clicksrcdir"
    fi
fi

AC_SUBST(clicksrcdir)
AC_SUBST(clickbuilddir)


dnl
dnl The rest of this file is based on Click 'configure.in'. You should not
dnl generally need to change it, although you may want to add to it.
dnl

CLICK_PROG_CC
AC_PROG_CPP
CLICK_PROG_CXX
AC_PROG_CXXCPP

AC_PATH_PROG(AR, ar)
AC_PATH_PROG(LD, ld)
AC_PATH_PROG(RANLIB, ranlib, :)
AC_PATH_PROG(STRIP, strip, :)

CLICK_PROG_INSTALL
CLICK_PROG_AUTOCONF
CLICK_PROG_GMAKE

if test -z "$GMAKE"; then
    AC_MSG_WARN([cannot find GNU make, not tracking dependencies])
fi


dnl
dnl Output
dnl

AC_OUTPUT
