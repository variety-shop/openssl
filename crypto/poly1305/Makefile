#
# OpenSSL/crypto/poly1305/Makefile
#

DIR=	poly1305
TOP=	../..
CC=	cc
CPP=    $(CC) -E
INCLUDES=
CFLAG=-g
AR=		ar r

POLY1305_ASM_OBJ=

CFLAGS= $(INCLUDES) $(CFLAG)
ASFLAGS= $(INCLUDES) $(ASFLAG)
AFLAGS= $(ASFLAGS)

GENERAL=Makefile

LIB=$(TOP)/libcrypto.a
LIBSRC=poly1305.c
LIBOBJ=poly1305.o $(POLY1305_ASM_OBJ)

SRC= $(LIBSRC)

HEADER= poly1305.h

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

poly1305-sparcv9.S:	asm/poly1305-sparcv9.pl
	$(PERL) asm/poly1305-sparcv9.pl > $@
poly1305-x86.s:		asm/poly1305-x86.pl
	$(PERL) asm/poly1305-x86.pl $(PERLASM_SCHEME) $(CFLAGS) $(PROCESSOR) > $@
poly1305-x86_64.s:	asm/poly1305-x86_64.pl
	$(PERL) asm/poly1305-x86_64.pl $(PERLASM_SCHEME) > $@

poly1305-%.S:	asm/poly1305-%.pl;	$(PERL) $< $(PERLASM_SCHEME) $@

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

links:

tags:
	ctags $(SRC)

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

update:	depend

depend:
	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.s *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

poly1305.o: poly1305.c poly1305.h
