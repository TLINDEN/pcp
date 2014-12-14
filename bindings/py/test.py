#!/usr/local/bin/python

from pypcp import *
from pprint import pprint

sk = Key("tom", "me@there")
sk.dump()

encoded = open("../../tests/key-bobby-sec", "r").read()

sk = Key(encoded=encoded, passphrase="b")
sk.dump()

p = open("../../tests/key-bobby-pub", "r").read()
pk = PublicKey(encoded=p)
pk.dump()

pprint(pk.masterpub)
