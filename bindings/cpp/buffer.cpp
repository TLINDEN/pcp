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

#include "buffer++.h"

using namespace std;
using namespace pcp;

Buf::Buf() {
  char name[] = "BUF";
  B = buffer_new(32, name);
}

Buf::Buf(Buffer *b) {
  B = b;
}

Buf::Buf(string name) {
  char *n = (char *)ucmalloc(name.length()+1);
  memcpy(n, name.c_str(), name.length());
  B = buffer_new(32, n);
  free(n);
}

Buf::Buf(string name, size_t blocksize) {
  char *n = (char *)ucmalloc(name.length()+1);
  memcpy(n, name.c_str(), name.length());
  B = buffer_new(blocksize, n);
  free(n);
}

Buf::~Buf() {
  buffer_free(B);
}

Buf& Buf::operator = (const Buf &b) {
  B = b.B;
  return *this;
}

void Buf::clear() {
  buffer_clear(B);
}

void Buf::rewind() {
  buffer_rewind(B);
}

void Buf::add(const void *data, size_t len) {
  buffer_add(B, data, len);
}

void Buf::add_buf(Buffer *src) {
  buffer_add_buf(B, src);
}

void Buf::add_string(string data) {
  buffer_add_str(B, data.c_str());
}

void Buf::add_hex(void *data, size_t len) {
  buffer_add_hex(B, data, len);
}

void Buf::resize(size_t len) {
  buffer_resize(B, len);
}

int Buf::done() {
  return buffer_done(B);
}

size_t Buf::get_chunk(void *buf, size_t len) {
  return buffer_get_chunk(B, buf, len);
}

unsigned char *Buf::get() {
  return buffer_get(B);
}

Buffer *Buf::get_buffer() {
  return B;
}

string Buf::get_str() {
  return string(buffer_get_str(B));
}

unsigned char *Buf::get_remainder() {
  return buffer_get_remainder(B);
}

size_t Buf::extract(void *buf, size_t offset, size_t len) {
  return buffer_extract(B, buf, offset, len);
}

uint8_t Buf::get8() {
  return buffer_get8(B);
}

uint16_t Buf::get16() {
  return buffer_get16(B);
}

uint32_t Buf::get32() {
  return buffer_get32(B);
}

uint64_t Buf::get64() {
  return buffer_get64(B);
}

uint16_t Buf::get16na() {
  return buffer_get16na(B);
}

uint32_t Buf::get32na() {
  return buffer_get32na(B);
}

uint64_t Buf::get64na() {
  return buffer_get64na(B);
}

uint8_t  Buf::last8() {
  return  buffer_last8(B);
}

uint16_t Buf::last16() {
  return buffer_last16(B);
}

uint32_t Buf::last32() {
  return buffer_last32(B);
}

uint64_t Buf::last64() {
  return buffer_last64(B);
}

size_t Buf::fd_read(FILE *in, size_t len) {
  return buffer_fd_read(B, in, len);
}

void Buf::add8(uint8_t v) {
  buffer_add8(B, v);
}

void Buf::add16(uint16_t v) {
  buffer_add16(B, v);
}

void Buf::add32(uint32_t v) {
  buffer_add32(B, v);
}

void Buf::add64(uint64_t v) {
  buffer_add64(B, v);
}

void Buf::add16be(uint16_t v) {
  buffer_add16be(B, v);
}

void Buf::add32be(uint32_t v) {
  buffer_add32be(B, v);
}

void Buf::add64be(uint64_t v) {
  buffer_add64be(B, v);
}

void Buf::dump() {
  buffer_dump(B);
}

void Buf::info() {
  buffer_info(B);
}

size_t Buf::size() {
  return buffer_size(B);
}

size_t Buf::left() {
  return buffer_left(B);
}
