#!/usr/local/bin/python

from ctypes import *
import platform

if platform.system() == 'Windows':
    sodium = cdll.LoadLibrary("libsodium")
    pcp    = cdll.LoadLibrary("libpcp1")
elif platform.system() == 'Darwin':
    sodium = cdll.LoadLibrary('libsodium.dylib')
    pcp    = cdll.LoadLibrary("libpcp1.dylib")
else:
    sodium = cdll.LoadLibrary("libsodium.so")
    pcp    = cdll.LoadLibrary("libpcp1.so")

crypto_box_NONCEBYTES = sodium.crypto_box_noncebytes()
crypto_box_PUBLICKEYBYTES = sodium.crypto_box_publickeybytes()
crypto_box_SECRETKEYBYTES = sodium.crypto_box_secretkeybytes()
crypto_box_ZEROBYTES = sodium.crypto_box_zerobytes()
crypto_box_BOXZEROBYTES = sodium.crypto_box_boxzerobytes()
crypto_box_MACBYTES = sodium.crypto_box_macbytes()
crypto_secretbox_KEYBYTES = sodium.crypto_secretbox_keybytes()
crypto_secretbox_NONCEBYTES = sodium.crypto_secretbox_noncebytes()
crypto_secretbox_ZEROBYTES = sodium.crypto_secretbox_zerobytes()
crypto_secretbox_BOXZEROBYTES = sodium.crypto_secretbox_boxzerobytes()
crypto_secretbox_MACBYTES = sodium.crypto_secretbox_macbytes()
crypto_sign_PUBLICKEYBYTES = sodium.crypto_sign_publickeybytes()
crypto_sign_SECRETKEYBYTES = sodium.crypto_sign_secretkeybytes()
crypto_sign_SEEDBYTES = sodium.crypto_sign_seedbytes()
crypto_sign_BYTES = sodium.crypto_sign_bytes()
crypto_stream_KEYBYTES = sodium.crypto_stream_keybytes()
crypto_stream_NONCEBYTES = sodium.crypto_stream_noncebytes()
crypto_generichash_BYTES = sodium.crypto_generichash_bytes()
crypto_scalarmult_curve25519_BYTES = sodium.crypto_scalarmult_curve25519_bytes()
crypto_scalarmult_BYTES = sodium.crypto_scalarmult_bytes()
crypto_generichash_BYTES_MAX = sodium.crypto_generichash_bytes_max()



print "'crypto_box_NONCEBYTES' => %d," % crypto_box_NONCEBYTES
print "'crypto_box_PUBLICKEYBYTES' => %d," % crypto_box_PUBLICKEYBYTES
print "'crypto_box_SECRETKEYBYTES' => %d," % crypto_box_SECRETKEYBYTES
print "'crypto_box_ZEROBYTES' => %d," % crypto_box_ZEROBYTES
print "'crypto_box_BOXZEROBYTES' => %d," % crypto_box_BOXZEROBYTES
print "'crypto_box_MACBYTES' => %d," % crypto_box_MACBYTES
print "'crypto_secretbox_KEYBYTES' => %d," % crypto_secretbox_KEYBYTES
print "'crypto_secretbox_NONCEBYTES' => %d," % crypto_secretbox_NONCEBYTES
print "'crypto_secretbox_ZEROBYTES' => %d," % crypto_secretbox_ZEROBYTES
print "'crypto_secretbox_BOXZEROBYTES' => %d," % crypto_secretbox_BOXZEROBYTES
print "'crypto_secretbox_MACBYTES' => %d," % crypto_secretbox_MACBYTES
print "'crypto_sign_PUBLICKEYBYTES' => %d," % crypto_sign_PUBLICKEYBYTES
print "'crypto_sign_SECRETKEYBYTES' => %d," % crypto_sign_SECRETKEYBYTES
print "'crypto_sign_SEEDBYTES' => %d," % crypto_sign_SEEDBYTES
print "'crypto_sign_BYTES' => %d," % crypto_sign_BYTES
print "'crypto_stream_KEYBYTES' => %d," % crypto_stream_KEYBYTES
print "'crypto_stream_NONCEBYTES' => %d," % crypto_stream_NONCEBYTES
print "'crypto_generichash_BYTES' => %d," % crypto_generichash_BYTES
print "'crypto_scalarmult_curve25519_BYTES' => %d," % crypto_scalarmult_curve25519_BYTES
print "'crypto_scalarmult_BYTES' => %d," % crypto_scalarmult_BYTES
print "'crypto_generichash_BYTES_MAX' => %d," % crypto_generichash_BYTES_MAX
