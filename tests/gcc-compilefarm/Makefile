PREFIX = $(HOME)/usr
BUILD  = $(HOME)/build

GITSODIUM = https://github.com/jedisct1/libsodium.git
GITPCP    = https://github.com/TLINDEN/pcp.git

DIRCFG   = Config-General-2.52
DIRTIE   = Tie-IxHash-1.23
DIRYAM   = YAML-0.84

GZCFG    = $(DIRCFG).tar.gz
GZTIE    = $(DIRTIE).tar.gz
GZYAM    = $(DIRYAM).tar.gz

CPANCFG  = http://search.cpan.org/CPAN/authors/id/T/TL/TLINDEN/$(GZCFG)
CPANTIE  = http://search.cpan.org/CPAN/authors/id/C/CH/CHORNY/$(GZTIE)
CPANYAM  = http://search.cpan.org/CPAN/authors/id/M/MS/MSTROUT/$(GZYAM)

HAVEPERL = $(PREFIX)/share/perl/5.10.1/Config/General.pm
HAVESODIUM = $(PREFIX)/lib/libsodium.a
SRCSODIUM = $(BUILD)/libsodium
SRCPCP    = $(BUILD)/pcp

all: prepare fetch config-sodium compile-sodium install-sodium config-pcp compile-pcp install-pcp test-pcp
	@echo done


prepare:
	if test ! -d $(PREFIX); then mkdir -p $(PREFIX); fi
	if test ! -d $(BUILD); then mkdir -p $(BUILD); fi

perl: prepare
	if test ! -f $(HAVEPERL); then \
		cd $(BUILD) && wget $(CPANCFG) && tar xvfz $(GZCFG); \
		cd $(BUILD)/$(DIRCFG) && perl Makefile.PL PREFIX=$(PREFIX) && make && make install; \
		cd $(BUILD) && wget $(CPANTIE) && tar xvfz $(GZTIE); \
		cd $(BUILD)/$(DIRTIE) && perl Makefile.PL PREFIX=$(PREFIX) && make && make install; \
		cd $(BUILD) && wget $(CPANYAM) && tar xvfz $(GZYAM); \
		cd $(BUILD)/$(DIRYAM) && perl Makefile.PL PREFIX=$(PREFIX) && make && make install; \
	fi


fetch: prepare
	if test ! -d $(SRCSODIUM); then \
		cd $(BUILD) && git clone $(GITSODIUM); \
	else \
		cd $(SRCSODIUM) && git pull; \
	fi
	if test ! -d $(SRCPCP); then \
		cd $(BUILD) && git clone $(GITPCP); \
	else \
		cd $(SRCPCP) && git pull; \
	fi

config-sodium:
	if test ! -f $(HAVESODIUM); then \
		cd $(SRCSODIUM) && ./autogen.sh; \
		cd $(SRCSODIUM) && ./configure --prefix=$(PREFIX); \
	fi

config-pcp:
	cd $(SRCPCP) && ./configure --prefix=$(PREFIX) --with-libsodium=$(PREFIX)

compile-sodium:
	if test ! -f $(HAVESODIUM); then \
		cd $(SRCSODIUM) && make; \
	fi

compile-pcp:
	cd $(SRCPCP) && make

install-sodium:
	if test ! -f $(HAVESODIUM); then \
		cd $(SRCSODIUM) && make install; \
	fi

install-pcp:
	cd $(SRCPCP) && make install

clean:
	cd $(SRCSODIUM) && make clean
	cd $(SRCPCP) && make clean
	rm -rf $(PREFIX)

test-pcp: perl
	ln -sf $(PREFIX)/share/perl/5.10.1 $(SRCPCP)/tests/lib
	cd $(SRCPCP) && make test
