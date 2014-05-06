/*
    This file is part of Pretty Curved Privacy (pcp1).

    Copyright (C) 2013-2014 T.v.Dein.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    You can contact me by mail: <tom AT vondein DOT org>.
*/


#ifndef _HAVE_PCP_CONTEXT_H
#define _HAVE_PCP_CONTEXT_H

#include "defines.h"
#include "platform.h"
#include "uthash.h"
#include "structs.h"
#include "mem.h"
#include "keyhash.h"

/**
 * \defgroup CONTEXT CONTEXT
 * @{

 A couple of context functions to catch errors and display them.
 The context also holds the key hashes.

 */


/** Create a new PCP Context.

    Sets all context pointers to NULL.

    \return the context object.
*/
PCPCTX *ptx_new();


/** Frees the memory allocated by the context. 

    \param[in] PCP Context object.
*/
void ptx_clean(PCPCTX *ptx);


/** Set an error message.

    This function gets a printf() like error message,
    which it stores in the global PCP_ERR variable
    and sets PCP_ERRSET to 1.

    \param[in] PCP Context object.

    \param[in] fmt printf() like format description.

    \param[in] ... format parameters, if any.
*/
void fatal(PCPCTX *ptx, const char * fmt, ...);

/** Prints error messages to STDERR, if there are some.

    FIXME: add something like this which returns the
    message.

    \param[in] PCP Context object.
*/
void fatals_ifany(PCPCTX *ptx);

/** Reset the error variables.

    This can be used to ignore previous errors.
    Use with care.

    \param[in] PCP Context object.
*/
void fatals_reset(PCPCTX *ptx);

/* same as fatal() but dies immediately */
void final(const char * fmt, ...);

void ptx_dump(PCPCTX *ptx);

#endif // _HAVE_PCP_CONTEXT_H
