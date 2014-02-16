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


#ifndef _HAVE_BUFFERPP_H
#define _HAVE_BUFFERPP_H

#include <pcp.h>
#include <string>
#include <iostream>


namespace pcp {
  class Buf {
  private:
    Buffer *B;

  public:
    Buf();
    Buf(Buffer *b);
    Buf(std::string name);
    Buf(std::string name, size_t blocksize);
    ~Buf();
    
    Buf& operator = (const Buf &b);

    
    void clear();
    void rewind();
    void add(const void *data, size_t len);
    void add_buf(Buffer *src);

    void add_string(std::string data);

    void add_hex(void *data, size_t len);
    void resize(size_t len);
    int done();
    size_t get_chunk(void *buf, size_t len);
    unsigned char *get();

    void dump();
    void info();
    size_t size();
    size_t left();

    std::string get_str();

    unsigned char *get_remainder();
    Buffer *get_buffer();

    size_t extract(void *buf, size_t offset, size_t len);
    uint8_t get8();
    uint16_t get16();
    uint32_t get32();
    uint64_t get64();
    uint16_t get16na();
    uint32_t get32na();
    uint64_t get64na();
    uint8_t  last8();
    uint16_t last16();
    uint32_t last32();
    uint64_t last64();
    size_t fd_read(FILE *in, size_t len);
    void add8(uint8_t v);
    void add16(uint16_t v);
    void add32(uint32_t v);
    void add64(uint64_t v);
    void add16be(uint16_t v);
    void add32be(uint32_t v);
    void add64be(uint64_t v);
  };
};

#endif // HAVE_BUFFERPP_H
