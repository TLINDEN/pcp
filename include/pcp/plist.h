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

/*
  Simple linked list wrappers,
  used for recipient- or keyid lists
*/

#ifndef _HAVE_PCP_PLIST_H
#define _HAVE_PCP_PLIST_H

#include <stdlib.h>
#include <stdio.h>

struct _plist_t {
  char *value;
  struct _plist_t *next;
  struct _plist_t *first;
};

typedef struct _plist_t plist_t;

static inline void p_add(plist_t **lst, char *value) {
  plist_t *newitem;
  plist_t *iter = *lst;

  newitem = (plist_t *)malloc(sizeof(plist_t));
  newitem->value = (char *)malloc(strlen(value) + 1);
  strncpy(newitem->value, value, strlen(value) + 1);
  newitem->next = NULL;
  
  if ( iter != NULL ) {
    while (iter->next != NULL ) {
      iter = iter->next;
    }
    newitem->first = iter->first;
    iter->next = newitem;
  }
  else {
    newitem->first = newitem;
    *lst = newitem;
  }
}

static inline void p_add_me(plist_t **lst) {
  char *me = (char *)malloc(13);
  strcpy(me, "__self__");
  p_add(lst, me);
  free(me);
}

static inline void p_clean(plist_t *lst) {
  plist_t *iter = lst->first;
  plist_t *tmp;

  while (iter != NULL) {
    tmp = iter;
    iter = iter->next;
    free(tmp->value);
    free(tmp);
  }

}

#endif /*  _HAVE_PCP_PLIST_H */
