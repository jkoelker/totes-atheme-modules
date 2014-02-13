# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([totes-atheme-modules], [0.1], [jason@koelker.net])
AC_CONFIG_AUX_DIR(autoconf)

AC_CONFIG_SRCDIR([modules])

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET

AC_ARG_WITH([atheme-prefix],
    [AS_HELP_STRING([--with-atheme-prefix=PATH],
                    [location of the atheme install prefix])],
    [export PKG_CONFIG_PATH=${withval}/lib/pkgconfig:${PKG_CONFIG_PATH}])

AC_ARG_WITH([modsubdir],
    [AC_HELP_STRING([--with-modsubdir=NAME],
                    [subdirectory of atheme MODDIR to install to])],
    [MODSUBDIR=$withval],
    [MODSUBDIR=totes])

AC_SUBST([MODSUBDIR])

BUILDSYS_SHARED_LIB
BUILDSYS_PROG_IMPLIB
LIBS="$LIBS $DYNAMIC_LD_LIBS"

AC_PATH_PROG(RANLIB, ranlib)

AC_PROG_CC_C99
AC_GNU_SOURCE
AC_C_BIGENDIAN
AC_PROG_MAKE_SET

AC_SUBST([PACKAGE], [AC_PACKAGE_TARNAME])
AC_SUBST([VERSION], [AC_PACKAGE_VERSION])

AC_DEFINE_UNQUOTED(PACKAGE, "$PACKAGE", [Name of package])
AC_DEFINE_UNQUOTED(VERSION, "$VERSION", [Version number of package])

PKG_CHECK_MODULES([atheme], [atheme-services])
PKG_CHECK_MODULES([mowgli], [libmowgli-2])

CPPFLAGS="$CPPFLAGS $atheme_CFLAGS $mowgli_CFLAGS"
LIBS="$LIBS $atheme_LIBS $mowgli_LIBS"

PKG_CHECK_VAR([MODDIR], [atheme-services], [MODDIR], [],
              [AC_MSG_ERROR([Cannot retrieve MODDIR pkgconfig variable])])

AC_CHECK_HEADER_STDBOOL

AC_OUTPUT([buildsys.mk extra.mk])
