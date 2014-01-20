/*
    This file is part of Pretty Curved Privacy (pcp1).

    Copyright (C) 2013 T. von Dein.

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


// used for recipient- or keyid lists

#ifndef _HAVE_PCP_PLIST_H
#define _HAVE_PCP_PLIST_H

#include <stdlib.h>

struct _plist_t {
  char *value;
  struct _plist_t *next;
};

typedef struct _plist_t plist_t;

static inline void p_add(plist_t **lst, char *value) {
  plist_t *newitem;
  plist_t *lst_iter = *lst;

  newitem = (plist_t *)malloc(sizeof(plist_t));
  newitem->value = malloc(strlen(value) + 1);
  strncpy(newitem->value, value, strlen(value) + 1);
  newitem->next = NULL;
  
  if ( lst_iter != NULL ) {
    while (lst_iter->next != NULL )
      lst_iter = lst_iter->next;
    lst_iter->next = newitem;
  }
  else
    *lst = newitem;
}

#endif // _HAVE_PCP_PLIST_H
