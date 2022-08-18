/*
 * A program for secure cleaning of free space on filesystems.
 *	-- wiping functions.
 *
 * Copyright (C) 2011 Bogdan Drozdowski, bogdandr (at) op.pl
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
 * along with this program; if not, write to the Free Software Foudation:
 *		Free Software Foundation
 *		51 Franklin Street, Fifth Floor
 *		Boston, MA 02110-1301
 *		USA
 */

#include "wfs_cfg.h"

#ifdef HAVE_STDLIB_H
# include <stdlib.h>	/* random(), srandom(), rand(), srand() */
#endif

#ifdef HAVE_LIBINTL_H
# include <libintl.h>	/* translation stuff */
#endif

#ifdef HAVE_LOCALE_H
# include <locale.h>
#endif

/* redefine the inline sig function from hfsp, each time with a different name */
#define sig(a,b,c,d) wfs_wipe_sig(a,b,c,d)
#include "wipefreespace.h"
#include "wfs_wiping.h"
#include "wfs_signal.h"

static const char * const msg_pattern     = N_("Using pattern");
static const char * const msg_random      = N_("random");

static int opt_verbose = 0;
static int opt_allzero = 0;
static unsigned long int wfs_npasses = PASSES;		/* Number of passes (patterns used) */
/* Taken from `shred' source */
static unsigned const int patterns[NPAT] =
{
	0x000, 0xFFF,					/* 1-bit */
	0x555, 0xAAA,					/* 2-bit */
	0x249, 0x492, 0x6DB, 0x924, 0xB6D, 0xDB6,	/* 3-bit */
	0x111, 0x222, 0x333, 0x444, 0x666, 0x777,
	0x888, 0x999, 0xBBB, 0xCCC, 0xDDD, 0xEEE	/* 4-bit */
#ifndef WFS_WANT_RANDOM
	/* Gutmann method says these are used twice. */
	, 0x555, 0xAAA, 0x249, 0x492, 0x924
#endif
};

/* ======================================================================== */

/**
 * Inintializes the wiping module.
 * \param npasses The number of wiping passes to use.
 * \param verbose Non-zero if verbose mode should be enabled.
 * \param allzero Non-zero if all patterns should be zero.
 */
void
init_wiping (
#ifdef WFS_ANSIC
	const unsigned long int number_of_passes, const int verbose, const int allzero)
#else
	number_of_passes, verbose, allzero)
	const unsigned long int number_of_passes;
	const int verbose;
	const int allzero;
#endif
{
	wfs_npasses = number_of_passes;
	opt_verbose = verbose;
	opt_allzero = allzero;
}

/* ======================================================================== */

/**
 * Fills the given buffer with one of predefined patterns.
 * \param pat_no Pass number.
 * \param buffer Buffer to be filled.
 * \param buflen Length of the buffer.
 * \param selected The array which tells which of the patterns have already been used.
 * \param FS The filesystem this wiping refers to.
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
	const wfs_fsid_t		FS )
#else
	pat_no,	buffer,	buflen,	selected, FS )
	unsigned long int 		pat_no;
	unsigned char * const 		buffer;
	const size_t 			buflen;
	int * const			selected;
	const wfs_fsid_t		FS;
#endif
		/*@requires notnull buffer @*/ /*@sets *buffer @*/
{

	size_t i;
#if (!defined HAVE_MEMCPY) && (!defined HAVE_STRING_H)
	size_t j;
#endif
	unsigned int bits;
	char tmp[8];
	int res;

	if ( (buffer == NULL) || (buflen == 0) ) return;

	/* De-select all patterns once every npasses calls. */
	if ( pat_no % wfs_npasses == 0 )
	{
		for ( i = 0; (i < NPAT) && (sig_recvd==0); i++ ) { selected[i] = 0; }
        }
        if ( sig_recvd != 0 ) return;
        pat_no %= wfs_npasses;

	if ( opt_allzero != 0 )
	{
		bits = 0;
	}
	else
	{
		/* The first, last and middle passess will be using a random pattern */
		if ( (pat_no == 0) || (pat_no == wfs_npasses-1) || (pat_no == wfs_npasses/2)
#ifndef WFS_WANT_RANDOM
			/* Gutmann method: first 4, 1 middle and last 4 passes are random */
			|| (pat_no == 1) || (pat_no == 2) || (pat_no == 3)
			|| (pat_no == wfs_npasses-2) || (pat_no == wfs_npasses-3)
			|| (pat_no == wfs_npasses-4)
#endif
		)
		{
#if (!defined __STRICT_ANSI__) && (defined HAVE_RANDOM)
			bits = (unsigned int) (random () & 0xFFF);
#else
			bits = (unsigned int) (rand () & 0xFFF);
#endif
		}
		else
		{	/* For other passes, one of the fixed patterns is selected. */
			do
			{
#if (!defined __STRICT_ANSI__) && (defined HAVE_RANDOM)
				i = (size_t) (random () % NPAT);
#else
				i = (size_t) (rand () % NPAT);
#endif
			}
			while ( (selected[i] == 1) && (sig_recvd == 0) );
			if ( sig_recvd != 0 ) return;
			bits = patterns[i];
			selected[i] = 1;
		}
    	}

        if ( sig_recvd != 0 ) return;
	/* Taken from `shred' source and modified */
	bits |= bits << 12;
	buffer[0] = (unsigned char) ((bits >> 4) & 0xFF);
	buffer[1] = (unsigned char) ((bits >> 8) & 0xFF);
	buffer[2] = (unsigned char) (bits & 0xFF);
	/* display the patterns when at least two '-v' command line options were given */
	if ( opt_verbose > 1 )
	{
		if ( ((pat_no == 0) || (pat_no == wfs_npasses-1) || (pat_no == wfs_npasses/2)
#ifndef WFS_WANT_RANDOM
			/* Gutmann method: first 4, 1 middle and last 4 passes are random */
			|| (pat_no == 1) || (pat_no == 2) || (pat_no == 3)
			|| (pat_no == wfs_npasses-2) || (pat_no == wfs_npasses-3)
			|| (pat_no == wfs_npasses-4)
#endif
			) && ( opt_allzero == 0 )
		 )
		{
			show_msg ( 1, msg_pattern, msg_random, FS );
		}
		else
		{
#if (!defined __STRICT_ANSI__) && (defined HAVE_SNPRINTF)
			res = snprintf (tmp, 7, "%02x%02x%02x", buffer[0], buffer[1], buffer[2] );
#else
			res = sprintf (tmp, "%02x%02x%02x", buffer[0], buffer[1], buffer[2] );
#endif
			tmp[7] = '\0';
			show_msg ( 1, msg_pattern, (res > 0)? tmp: "??????", FS );
		}
	}
	for (i = 3; (i < buflen / 2) && (sig_recvd == 0); i *= 2)
	{
#ifdef HAVE_MEMCPY
		memcpy (buffer + i, buffer, i);
#else
# if defined HAVE_STRING_H
		strncpy ((char *) (buffer + i), (char *) buffer, i);
# else
		for ( j=0; j < i; j++ )
		{
			buffer [ i + j ] = buffer[j];
		}
# endif
#endif
	}
        if ( sig_recvd != 0 ) return;
	if (i < buflen)
	{
#ifdef HAVE_MEMCPY
		memcpy (buffer + i, buffer, buflen - i);
#else
# if defined HAVE_STRING_H
		strncpy ((char *) (buffer + i), (char *) buffer, buflen - i);
# else
		for ( j=0; j<buflen - i; j++ )
		{
			buffer [ i + j ] = buffer[j];
		}
# endif
#endif
	}
}

