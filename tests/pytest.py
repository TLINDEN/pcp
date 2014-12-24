#!/usr/bin/env python

#
#    This file is part of Pretty Curved Privacy (pcp1).
#
#    Copyright (C) 2013-2015 T. von Dein.
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#    You can contact me by mail: <tlinden AT cpan DOT org>.
#

import sys, os
from pprint import pprint

os.environ['PCPCP_MAKE_TEST'] = "1"
sys.path.append('../bindings/py')
from pypcp import *

orig = "hello world"
Ali = None
Bob = None


class Peer(object):
    def __init__(self, sec, pub, passwd):
        self.sec = 0
        self.pub = 0
        self.ctx = Context()

        if sec:
            self.sec = self.importkey(sec, passwd)
            self.ctx.addkey(self.sec)
        if pub:
            self.pub = self.importkey(pub, public=True)
            self.ctx.recipients(self.pub)
       
        

    def importkey(self, filename, passwd=None, secret=True, public=False):
        raw = open(filename, "r").read()
        if secret and not public:
            key = Key(encoded=raw, passphrase=passwd)
            return key
        else:
            key = PublicKey(encoded=raw)
            return key


def impkeys():
    global Ali
    global Bob
    Ali = Peer("key-alicia-sec", "key-bobby-pub", "a")
    Bob = Peer("key-bobby-sec", "key-alicia-pub", "b")

    # no exception here - done
    return True

def asym(armor=True, sign=False):
    if Ali is None:
        impkeys()
        
    # Alice encrypt => Bob
    encrypted = Ali.ctx.encrypt(source=orig, armor=armor, sign=sign)

    # Bob decrypt from Alice
    clear = Bob.ctx.decrypt(source=encrypted, verify=sign)

    if clear == orig:
        return True
    else:
        return False

def asymarmor():
    return asym(armor=True)

def asymraw():
    return asym(armor=False)

def asymsign():
    return asym(sign=True)

def asymanon():
    Ali = Peer(None,            "key-bobby-pub", None)
    Bob = Peer("key-bobby-sec", None,            "b")
    
    # Anon encrypt => Bob
    encrypted = Ali.ctx.encrypt(source=orig)

    # Bob decrypt from Anon
    clear = Bob.ctx.decrypt(source=encrypted)

    if clear == orig:
        return True
    else:
        return False

    return True

def sym(armor=True):
    # always required
    ctx = Context()

    # symmetric encryption (self mode)
    encrypted = ctx.encrypt(source=orig, passphrase="x", armor=armor)
    
    # decrypt
    clear = ctx.decrypt(source=encrypted, passphrase="x")
    
    if clear == orig:
        return True
    else:
        return False

def symarmor():
    return sym(armor=True)

def symraw():
    return sym(armor=False)

def defun(name):
    if not globals()[name]():
        print "%s: failed" % name
        exit(1)
    else:
        print "%s: ok" % name
        return True


if len(sys.argv) == 2:
    if defun(sys.argv[1]):
        exit(0)
else:
    # execute all
    for func in ["impkeys", "asymarmor", "asymraw", "asymsign", "symarmor", "symraw"]:
        defun(func)
    exit(0)




