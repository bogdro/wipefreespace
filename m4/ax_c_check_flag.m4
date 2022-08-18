#####
#
# SYNOPSIS
#
#   AX_C_CHECK_FLAG(FLAG-TO-CHECK,[ACTION-IF-SUCCESS],[ACTION-IF-FAILURE])
#
# DESCRIPTION
#
#   This macro tests if the C compiler supports the flag FLAG-TO-CHECK
#   If successfull execute ACTION-IF-SUCCESS otherwise ACTION-IF-FAILURE
#
#   Thanks to Bogdan Drozdowski <bogdandr@op.pl> for testing and bug-fixes
#
# LAST MODIFICATION
#
#  2007-11-17
#
# COPYLEFT
#
#  Copyright (c) 2007 Francesco Salvestrini <salvestrini@users.sourceforge.net>
#
#  This code is inspired from KDE_CHECK_COMPILER_FLAG macro
#
#  Copying and distribution of this file, with or without
#  modification, are permitted in any medium without royalty provided
#  the copyright notice and this notice are preserved
#
##########################################################################
AC_DEFUN([AX_C_CHECK_FLAG],[
	AC_REQUIRE([AC_PROG_CC])

	if ( test "x$SED" = "x" ); then

		AC_CHECK_PROG([ISSED], [sed], [yes], [no])
		if ( test "x$ISSED" = "xyes" ); then

			AC_PATH_PROG([SED], [sed])
		fi
	fi

	if ( test "x$SED" != "x" && test "x$SED" != "xno" ); then

		# check if we already checked for the "-Werror" flag, needed for every command line
		if ( test "x$ax_priv_cv_C_check_flag_Werror" = "x" ); then

			save_CFLAGS="$CFLAGS"
			# we did not check? then check for "-Werror" now
			CFLAGS="$CFLAGS -Werror"
			cat > conftest.c << _AX_C_CHECK_FLAG_EOF1

int main (
/*
 * Look in the autoconf manual, chapter "Existing Tests", section "Compilers and Preprocessors",
 * subsection "C Compiler" for what is going on below.
 * The 'void' is required for -Wstrict-prototypes to pass.
 */
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	void
#endif
)
{
	return 0;
}
/* Leave the last line blank, or we get a warning and die. */

_AX_C_CHECK_FLAG_EOF1

			if AC_TRY_COMMAND([[$CC $CFLAGS conftest.c > /dev/null 2>&1]]); then
				eval "ax_priv_cv_C_check_flag_Werror=yes"
			else
				eval "ax_priv_cv_C_check_flag_Werror=no"
			fi
			CFLAGS="$save_CFLAGS"
		fi

#	gcc '-Df(x)=(x*x)' '-DA=int r[5]={1,2,3,4,5}' is valid!
		flag=`echo "x$1" | $SED 'y: .=/+-,(){}*&!~#%^<>?;":_dedpmc____mrnnhpx__qsq:'`
		flag=`echo "$flag" | $SED 's:\@<:@:_:' | $SED "y:'@:>@:a_:"`	# Apostrophe, left & right square brackets
		flag=`echo "$flag" | $SED 's:^x::'`		# Remove the leading 'x' put there for 'echo'
		AC_CACHE_CHECK([[whether the C compiler accepts $1 ]],
			[[ax_cv_C_check_flag_$flag]],[

			AC_LANG_PUSH([C])

			save_CFLAGS="$CFLAGS"
			flag_cmd="$1"
			# if -Werror supported, add it AT THE BEGINNING
			if ( test "x$ax_priv_cv_C_check_flag_Werror" = "xyes" ); then
				CFLAGS="-Werror $CFLAGS"
			fi
			cat > conftest.c << _AX_C_CHECK_FLAG_EOF2

int main (
/*
 * Look in the autoconf manual, chapter "Existing Tests", section "Compilers and Preprocessors",
 * subsection "C Compiler" for what is going on below.
 * The 'void' is required for -Wstrict-prototypes to pass.
 */
#if defined (__STDC__) || defined (_AIX) \
	|| (defined (__mips) && defined (_SYSTYPE_SVR4)) \
	|| defined(WIN32) || defined(__cplusplus)
	void
#endif
)
{
	return 0;
}
/* Leave the last line blank, or we get a warning and die. */

_AX_C_CHECK_FLAG_EOF2

			# Try the requested option here
			if AC_TRY_COMMAND([[echo $CFLAGS $flag_cmd conftest.c | xargs $CC > conftest.err 2>&1]]);
			then
				# OK. Command succeeded, but the option still might be invalid.
				# Look for warnings in the output file
				if ( grep -q -- "'$1'" conftest.err ); then
					# we assume "grep" found a line saying
					# <unrecognized option '-blah'>
					# we do NOT look for the words, because
					# localization of the compiler (message translation)
					# would kill us
					eval "ax_cv_C_check_flag_$flag=no"
				else
					eval "ax_cv_C_check_flag_$flag=yes"
				fi
			else
				eval "ax_cv_C_check_flag_$flag=no"
			fi

			CFLAGS="$save_CFLAGS"

			AC_LANG_POP
		])

		AS_IF([[eval "test \"`echo '$ax_cv_C_check_flag_'$flag`\" = yes"]],[[
			:
			$2
		]],[[
			:
			$3
		]])
	fi
])
