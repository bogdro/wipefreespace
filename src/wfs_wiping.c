/*
 * A program for secure cleaning of free space on filesystems.
 *	-- wiping functions.
 *
 * Copyright (C) 2011-2022 Bogdan Drozdowski, bogdro (at) users.sourceforge.net
 * License: GNU General Public License, v2+
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "wfs_cfg.h"

#include <stdio.h>	/* snprintf() */

#ifdef HAVE_STRING_H
# if ((!defined STDC_HEADERS) || (!STDC_HEADERS)) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>
#endif

#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif

#ifdef AX_STRCASECMP_HEADER
# include AX_STRCASECMP_HEADER
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>	/* random(), srandom(), rand(), srand() */
#endif

#ifdef HAVE_LIBINTL_H
# include <libintl.h>	/* translation stuff */
#endif

#ifdef HAVE_LOCALE_H
# include <locale.h>
#endif

#include "wipefreespace.h"
#include "wfs_wiping.h"
#include "wfs_signal.h"

enum wfs_method
{
	WFS_METHOD_GUTMANN,
	WFS_METHOD_RANDOM,
	WFS_METHOD_SCHNEIER,
	WFS_METHOD_DOD
};

static const char * const msg_pattern     = N_("Using pattern");
static const char * const msg_random      = N_("random");

static int opt_verbose = 0;
static int opt_allzero = 0;
static enum wfs_method opt_method = WFS_METHOD_GUTMANN;
static unsigned long int wfs_npasses = WFS_PASSES;		/* Number of passes (patterns used) */

/* Taken from `shred' source */
static const unsigned int patterns_random[] =
{
	0x000, 0xFFF,					/* 1-bit */
	0x555, 0xAAA,					/* 2-bit */
	0x249, 0x492, 0x6DB, 0x924, 0xB6D, 0xDB6,	/* 3-bit */
	0x111, 0x222, 0x333, 0x444, 0x666, 0x777,
	0x888, 0x999, 0xBBB, 0xCCC, 0xDDD, 0xEEE	/* 4-bit */
};

static const unsigned int patterns_gutmann[] =
{
	0x000, 0xFFF,					/* 1-bit */
	0x555, 0xAAA,					/* 2-bit */
	0x249, 0x492, 0x6DB, 0x924, 0xB6D, 0xDB6,	/* 3-bit */
	0x111, 0x222, 0x333, 0x444, 0x666, 0x777,
	0x888, 0x999, 0xBBB, 0xCCC, 0xDDD, 0xEEE,	/* 4-bit */
	/* Gutmann method says these are used twice. */
	0x555, 0xAAA, 0x249, 0x492, 0x924
};

static const unsigned int patterns_schneier[] =
{
	0xFFF, 0x000
};

static unsigned int patterns_dod[] =
{
	0xFFF, 0x000	/* will be filled in later */
};

#ifdef TEST_COMPILE
# undef WFS_ANSIC
#endif

/* ======================================================================== */

#ifdef HAVE_STRCASECMP
# define WFS_STRCASECMP strcasecmp
#else
# ifndef WFS_ANSIC
static int wfs_compare WFS_PARAMS ((const char string1[], const char string2[]));
# endif

# define WFS_TOUPPER(c) ((char)( ((c) >= 'a' && (c) <= 'z')? ((c) & 0x5F) : (c) ))

/**
 * Compares the given strings case-insensitively.
 * \param string1 The first string.
 * \param string2 The second string.
 * \return 0 if the strings are equal, -1 is string1 is "less" than string2 and 1 otherwise.
 */
static int
wfs_compare (
# ifdef WFS_ANSIC
	const char string1[], const char string2[])
# else
	string1, string2)
	const char string1[];
	const char string2[];
# endif
{
	size_t i, len1, len2;
	char c1, c2;

	if ( (string1 == NULL) && (string2 == NULL) )
	{
		return 0;
	}
	else if ( string1 == NULL )
	{
		return -1;
	}
	else if ( string2 == NULL )
	{
		return 1;
	}
	else
	{
		/* both strings not-null */
		len1 = strlen (string1);
		len2 = strlen (string2);
		if ( len1 < len2 )
		{
			return -1;
		}
		else if ( len1 > len2 )
		{
			return 1;
		}
		else
		{
			/* both lengths equal */
			for ( i = 0; i < len1; i++ )
			{
				c1 = WFS_TOUPPER (string1[i]);
				c2 = WFS_TOUPPER (string2[i]);
				if ( c1 < c2 )
				{
					return -1;
				}
				else if ( c1 > c2 )
				{
					return 1;
				}
			}
		}
	}
	return 0;
}
# define WFS_STRCASECMP wfs_compare
#endif /* HAVE_STRCASECMP */

/* ======================================================================== */

#ifndef WFS_ANSIC
static int wfs_is_pass_random WFS_PARAMS ((const unsigned long int pat_no,
	const enum wfs_method method));
#endif

/**
 * Tells if the given wiping pass for the given method should be using a random pattern.
 * \param pat_no Pass number.
 * \param method The wiping method.
 * \return 1 if the should be random, 0 otherwise.
 */
static int
wfs_is_pass_random (
#ifdef WFS_ANSIC
	const unsigned long int pat_no, const enum wfs_method method)
#else
	pat_no, method)
	const unsigned long int pat_no;
	const enum wfs_method method;
#endif
{
	if ( method == WFS_METHOD_GUTMANN )
	{
		/* Gutmann method: first 4, 1 middle and last 4 passes are random */
		if ( (pat_no == 0) || (pat_no == wfs_npasses-1) || (pat_no == wfs_npasses/2)
			|| (pat_no == 1) || (pat_no == 2) || (pat_no == 3)
			|| (pat_no == wfs_npasses-2) || (pat_no == wfs_npasses-3)
			|| (pat_no == wfs_npasses-4) )
		{
			return 1;
		}
	}
	else if ( method == WFS_METHOD_RANDOM )
	{
		/* The first, last and middle passess will be using a random pattern */
		if ( (pat_no == 0) || (pat_no == wfs_npasses-1) || (pat_no == wfs_npasses/2) )
		{
			return 1;
		}
	}
	else if ( method == WFS_METHOD_SCHNEIER )
	{
		/* the third (number 2 when indexed from 0) and later passes are random */
		if ( pat_no >= 2 )
		{
			return 1;
		}
	}
	else if ( method == WFS_METHOD_DOD )
	{
		/* the third (number 2 when indexed from 0) pass is random */
		if ( pat_no >= 2 )
		{
			return 1;
		}
	}
	return 0;
}

/* ======================================================================== */

/**
 * Inintializes the wiping module.
 * \param npasses The number of wiping passes to use.
 * \param verbose Non-zero if verbose mode should be enabled.
 * \param allzero Non-zero if all patterns should be zero.
 * \param method The wiping method to use.
 * \return The number of wiping passes that would be used by default.
 */
unsigned long int
init_wiping (
#ifdef WFS_ANSIC
	unsigned long int number_of_passes, const int verbose,
	const int allzero, const char * const method)
#else
	number_of_passes, verbose, allzero, method)
	unsigned long int number_of_passes;
	const int verbose;
	const int allzero;
	const char * const method;
#endif
{
	opt_verbose = verbose;
	opt_allzero = allzero;
	wfs_npasses = number_of_passes;

	if ( method != NULL )
	{
		if ( WFS_STRCASECMP (method, "gutmann") == 0 )
		{
			opt_method = WFS_METHOD_GUTMANN;
			/* the number of passes is the number of predefined patterns
				+ the number of random patterns. */
			number_of_passes = sizeof (patterns_gutmann)/sizeof (patterns_gutmann[0])
				+ 4 + 1 + 4;
		}
		else if ( WFS_STRCASECMP (method, "random") == 0 )
		{
			opt_method = WFS_METHOD_RANDOM;
			/* the number of passes is the number of predefined patterns
				+ the number of random patterns. */
			number_of_passes = sizeof (patterns_random)/sizeof (patterns_random[0])
				+ 1 + 1 + 1;
		}
		else if ( WFS_STRCASECMP (method, "schneier") == 0 )
		{
			opt_method = WFS_METHOD_SCHNEIER;
			/* the number of passes is the number of predefined patterns
				+ the number of random patterns. */
			number_of_passes = sizeof (patterns_schneier)/sizeof (patterns_schneier[0])
				+ 5;
		}
		else if ( WFS_STRCASECMP (method, "dod") == 0 )
		{
			opt_method = WFS_METHOD_DOD;
			/* fill the patterns with a random byte and its complement */
#if (!defined __STRICT_ANSI__) && (defined HAVE_RANDOM)
			patterns_dod[0] = (unsigned int)random ();
#else
			patterns_dod[0] = (unsigned int)rand ();
#endif
			patterns_dod[1] = ~patterns_dod[0];
			/* the number of passes is the number of predefined patterns
				+ the number of random patterns. */
			number_of_passes = sizeof (patterns_dod)/sizeof (patterns_dod[0])
				+ 1;
		}
	}
	else
	{
		opt_method = WFS_METHOD_GUTMANN;
		/* the number of passes is the number of predefined patterns
			+ the number of random patterns. */
		number_of_passes = sizeof (patterns_gutmann)/sizeof (patterns_gutmann[0])
			+ 4 + 1 + 4;
	}
	if ( wfs_npasses == 0 )
	{
		/* use the default or the parameter */
		wfs_npasses = number_of_passes;
	}
	if ( wfs_npasses == 0 )
	{
		/* use the default */
		wfs_npasses = WFS_PASSES;
		number_of_passes = WFS_PASSES;
	}
	return number_of_passes;
}

/* ======================================================================== */

/**
 * Fills the given buffer with one of predefined patterns.
 * \param pat_no Pass number.
 * \param buffer Buffer to be filled.
 * \param buflen Length of the buffer.
 * \param selected The array which tells which of the patterns have already been used.
 * \param wfs_fs The filesystem this wiping refers to.
 */
void
#ifdef WFS_ANSIC
WFS_ATTR ((nonnull))
#endif
fill_buffer (
#ifdef WFS_ANSIC
	unsigned long int 		pat_no,
	unsigned char * const 		buffer,
	const size_t 			buflen,
	int * const			selected,
	const wfs_fsid_t		wfs_fs )
#else
	pat_no,	buffer,	buflen,	selected, wfs_fs )
	unsigned long int 		pat_no;
	unsigned char * const 		buffer;
	const size_t 			buflen;
	int * const			selected;
	const wfs_fsid_t		wfs_fs;
#endif
		/*@requires notnull buffer @*/ /*@sets *buffer @*/
{

	size_t i;
	unsigned int bits;
	char tmp[8];
	int res;
	size_t npat;

	if ( (buffer == NULL) || (buflen == 0) )
	{
		return;
	}

	if ( opt_method == WFS_METHOD_GUTMANN )
	{
		npat = sizeof (patterns_gutmann)/sizeof (patterns_gutmann[0]);
	}
	else if ( opt_method == WFS_METHOD_RANDOM )
	{
		npat = sizeof (patterns_random)/sizeof (patterns_random[0]);
	}
	else if ( opt_method == WFS_METHOD_SCHNEIER )
	{
		npat = sizeof (patterns_schneier)/sizeof (patterns_schneier[0]);
	}
	else if ( opt_method == WFS_METHOD_DOD )
	{
		npat = sizeof (patterns_dod)/sizeof (patterns_dod[0]);
	}
	else
	{
		return;
	}

	if ( selected != NULL )
	{
		for ( i = 0; i < npat; i++ )
		{
			if ( selected[i] == 0 )
			{
				break;
			}
		}
		if ( (i >= npat) && (wfs_is_pass_random (pat_no, opt_method) != 1) )
		{
			/* no patterns left and this is not a "random" pass - deselect all the patterns */
			for ( i = 0; (i < npat) && (sig_recvd == 0); i++ )
			{
				selected[i] = 0;
			}
		}
	}
        if ( sig_recvd != 0 )
	{
		return;
	}
        pat_no %= wfs_npasses;

	if ( opt_allzero != 0 )
	{
		bits = 0;
	}
	else
	{
		if ( wfs_is_pass_random (pat_no, opt_method) == 1 )
		{
#if (!defined __STRICT_ANSI__) && (defined HAVE_RANDOM)
			bits = (unsigned int) ((size_t)random () & 0xFFF);
#else
			bits = (unsigned int) ((size_t)rand () & 0xFFF);
#endif
		}
		else
		{	/* For other passes, one of the fixed patterns is selected. */
			if ( (opt_method == WFS_METHOD_GUTMANN)
				|| (opt_method == WFS_METHOD_RANDOM) )
			{
				do
				{
#if (!defined __STRICT_ANSI__) && (defined HAVE_RANDOM)
					i = (size_t) ((size_t)random () % npat);
#else
					i = (size_t) ((size_t)rand () % npat);
#endif
					if ( selected == NULL )
					{
						break;
					}
					else if ( selected[i] == 0 )
					{
						break;
					}
				}
				while ( sig_recvd == 0 );
				if ( sig_recvd != 0 )
				{
					return;
				}
			}
			else
			{
				/* other methods use their patterns in sequence */
				i = pat_no;
			}
			if ( opt_method == WFS_METHOD_GUTMANN )
			{
				bits = patterns_gutmann[i];
			}
			else if ( opt_method == WFS_METHOD_RANDOM )
			{
				bits = patterns_random[i];
			}
			else if ( opt_method == WFS_METHOD_SCHNEIER )
			{
				bits = patterns_schneier[i];
			}
			else /*if ( opt_method == WFS_METHOD_DOD )*/
			{
				bits = patterns_dod[i] & 0xFFF;
			}
			if ( selected != NULL )
			{
				selected[i] = 1;
			}
		}
    	}

        if ( sig_recvd != 0 )
	{
		return;
	}

	/* Taken from `shred' source and modified */
	bits |= bits << 12;

	/* display the patterns when at least two '-v' command line options were given */
	if ( opt_verbose > 1 )
	{
		if ( (wfs_is_pass_random (pat_no, opt_method) == 1)
			&& (opt_allzero == 0) )
		{
			wfs_show_msg ( 1, msg_pattern, msg_random, wfs_fs );
		}
		else
		{
#if (!defined __STRICT_ANSI__) && (defined HAVE_SNPRINTF)
			res = snprintf (tmp, sizeof (tmp) - 1, "%02x%02x%02x",
				(unsigned char) ((bits >> 4) & 0xFF),
				(unsigned char) ((bits >> 8) & 0xFF),
				(unsigned char) (bits & 0xFF) );
#else
			res = sprintf (tmp, "%02x%02x%02x",
				(unsigned char) ((bits >> 4) & 0xFF),
				(unsigned char) ((bits >> 8) & 0xFF),
				(unsigned char) (bits & 0xFF) );
#endif
			tmp[sizeof (tmp) - 1] = '\0';
			wfs_show_msg ( 1, msg_pattern, (res > 0)? tmp: "??????", wfs_fs );
		}
	}
	buffer[0] = (unsigned char) ((bits >> 4) & 0xFF);
	if ( buflen > 1 )
	{
		buffer[1] = (unsigned char) ((bits >> 8) & 0xFF);
	}
	if ( buflen > 2 )
	{
		buffer[2] = (unsigned char) (bits & 0xFF);
	}
	for (i = 3; ((i << 1) < buflen) && (sig_recvd == 0); i <<= 1)
	{
		WFS_MEMCOPY (buffer + i, buffer, i);
	}
        if ( sig_recvd != 0 )
	{
		return;
	}
	if (i < buflen)
	{
		WFS_MEMCOPY (buffer + i, buffer, buflen - i);
	}
}
