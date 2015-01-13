/*
    This file is part of Pretty Curved Privacy (pcp1).

    Copyright (C) 2013 T.Linden.

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

    You can contact me by mail: <tlinden AT cpan DOT org>.
*/


#ifndef _HAVE_PCP_MEM
#define _HAVE_PCP_MEM

#include <string.h>
#include <stdlib.h>
#include <sodium.h>
#include "defines.h"
#include "platform.h"

/*  simple malloc()  wrapper  */
/*  behaves like calloc(), which */
/*  I don't have here. */
/*   */
/*  exits if there's no more memory */
/*  available. */
void *ucmalloc(size_t s);

/* same as ucmalloc, but uses secure allocation */
void *smalloc(size_t s);

/*  the same but it fills the pointer with random values */
void *urmalloc(size_t s);

/*  same as urmalloc(), but uses secure allocation using sodium_malloc() */
void *srmalloc(size_t s);

/* resize a a pointer and fill the added remainder with zeroes */
void *ucrealloc(void *d, size_t oldlen, size_t newlen);

/* clear and free */
void ucfree(void *d, size_t len);

/* same, but free a sodium pointer */
void sfree(void *d);

#endif /*  _HAVE_PCP_MEM */
