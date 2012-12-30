dnl LambdaMOO-specific version of AC_FUNC_CHECK, uses <assert.h> instead of
dnl <ctype.h>, since OSF/1's <ctype.h> includes <sys/types.h> which includes
dnl <sys/select.h> which declares select() correctly in conflict with the
dnl bogus `extern char foo();' declaration below.  This change is adapted
dnl from autoconf-2.4, which we ought to start using at some point.
dnl
undefine([AC_FUNC_CHECK])dnl
define(AC_FUNC_CHECK,
[ifelse([$3], , [AC_COMPILE_CHECK($1, [#include <assert.h>], [
/* The GNU C library defines this for functions which it implements
    to always fail with ENOSYS.  Some functions are actually named
    something starting with __ and the normal name is an alias.  */
#if defined (__stub_$1) || defined (__stub___$1)
choke me
#else
/* Override any gcc2 internal prototype to avoid an error.  */
extern char $1(); $1();
#endif
],
$2)], [AC_COMPILE_CHECK($1, [#include <assert.h>], [
/* The GNU C library defines this for functions which it implements
    to always fail with ENOSYS.  Some functions are actually named
    something starting with __ and the normal name is an alias.  */
#if defined (__stub_$1) || defined (__stub___$1)
choke me
#else
/* Override any gcc2 internal prototype to avoid an error.  */
extern char $1(); $1();
#endif
],
$2, $3)])dnl
])dnl


AC_DEFUN(AC_CHECK_OPENSSL,[
  AC_SUBST(OPENSSL_LIBS)
  AC_SUBST(OPENSSL_INCLUDES)
  AC_ARG_WITH(openssl,
    [[  --without-openssl       Compile without OpenSSL]],
      if test "x$withval" = "xno" ; then
        without_openssl=yes
      elif test "x$withval" != "xyes" ; then
        with_arg=$withval/include:-L$withval/lib
      fi)
  if test "x$without_openssl" != "xyes" -a "x$with_arg" = "x"; then
    AC_CHECK_PROG([PKGCONFIG], [pkg-config], [pkg-config], [no])
    if test "x$PKGCONFIG" != "xno"; then
      AC_MSG_CHECKING([for OpenSSL])
      OPENSSL_LIBS=$($PKGCONFIG --libs openssl)
      OPENSSL_INCLUDES=$($PKGCONFIG --cflags openssl)
      if test "x$OPENSSL_LIBS" != "x" -o "x$OPENSSL_INCLUDES" != "x"; then
        AC_MSG_RESULT([yes])
        without_openssl=yes
        have_openssl=yes
      else
        AC_MSG_RESULT([no])
      fi
    fi
  fi
  if test "x$without_openssl" != "xyes" ; then
    AC_MSG_CHECKING(for ssl.h)
    for i in $with_arg \
                /usr/include: \
                /usr/local/include:"-L/usr/local/lib" \
                /usr/local/ssl/include:"-L/usr/local/ssl/lib" \
                /usr/pkg/include:"-L/usr/pkg/lib" \
                /usr/contrib/include:"-L/usr/contrib/lib" \
                /usr/freeware/include:"-L/usr/freeware/lib32" \
                /sw/include:"-L/sw/lib" \
                /cw/include:"-L/cw/lib" \
                /boot/home/config/include:"-L/boot/home/config/lib"; do

      incl=`echo "$i" | sed 's/:.*//'`
      lib=`echo "$i" | sed 's/.*://'`
      if test -f $incl/openssl/ssl.h; then
        AC_MSG_RESULT($incl/openssl/ssl.h)
        ldflags_old="$LDFLAGS"
        LDFLAGS="$lib -lssl -lcrypto"
        save_LIBS="$LIBS"
        LIBS="-lssl -lcrypto $LIBS"
        AC_CHECK_LIB(ssl, RSA_new, [
          AC_DEFINE(HAVE_OPENSSL, 1, [define if you have OpenSSL])
          have_openssl=yes
          OPENSSL_LIBS="$lib -lssl -lcrypto"
          if test "x$incl" != "x/usr/include"; then
            OPENSSL_INCLUDES="-I$incl"
          fi
        ])
        LIBS="$save_LIBS"
        LDFLAGS="$ldflags_old"
        break
      fi
    done
    if test "x$have_openssl" != "xyes"; then
      AC_MSG_RESULT(not found)
    fi
  fi
])
