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

/*
  Simple wrapper around FILE streams or Buffers, depending
  how the user initialized them. The Pcpstream object behaves
  always the same and it doesn't matter how it's backed.

  We use it in the lib, e.g. in the crypto routines. That way
  we can support blockwise crypto on buffers or files.

  Streams are, just like iostreams in c++, either output or
  input mode.
*/

#ifndef HAVE_PCP_PCPSTEAM_H
#define HAVE_PCP_PCPSTEAM_H

#include <stdio.h>
#include "mem.h"
#include "util.h"
#include "defines.h"
#include "buffer.h"

struct _pcp_stream_t {
  FILE *fd;
  Buffer *b;
  uint8_t is_buffer;
  uint8_t eof;
  uint8_t err;
};

typedef struct _pcp_stream_t Pcpstream;

/* initialize a new empty stream */
Pcpstream *ps_init(void);

/* create a new stream, backed with open file
   maybe used for in- or output */
Pcpstream *ps_new_file(FILE *backendfd);

/* create a new istream, backed with filled buffer */
Pcpstream *ps_new_inbuffer(Buffer *b);

/* create a new ostream, backed with buffer, which we allocate */
Pcpstream *ps_new_outbuffer();

/* read n bytes from the stream into given buf, return read size.
   if there's nothing more to read, it returns 0.
   sets eof=1 if end of file or end of buffer has been reached.
   sets err=1 if an error occurred, fatals() maybe set, or errno */
size_t ps_read(Pcpstream *stream, void *buf, size_t readbytes);

/* write n bytes from the given buf to the stream, return the
   number of bytes written. in case of errors it returns 0 and
   sets eof and err respectively as ps_read() does. */
size_t ps_write(Pcpstream *stream, void *buf, size_t writebytes);

/* return the current read or write offset */
size_t ps_tell(Pcpstream *stream);

/* closes the stream and frees allocated memory, if present */
void ps_close(Pcpstream *stream);

/* returns true (1) of we reached EOF */
int ps_end(Pcpstream *stream);

/* returns true (1) of we had an error */
int ps_err(Pcpstream *stream);


#endif // HAVE_PCP_PCPSTEAM_H
