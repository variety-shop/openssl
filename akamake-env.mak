#! /usr/bin/make -f

# FILE OFFSET BITS
$P/configure.ts : $P/CONFIGFLAGS := $($P/CONFIGFLAGS) $(filter %=64,-D_FILE_OFFSET_BITS=$(BUILDENV.FILE_OFFSET_BITS-master))

# CONFIGURE PROFILE: these are mutually-exclusive

ifneq (,$(AKAMAKE-ALSI7-BUILD)$(AKAMAKE-ALSI7-LITE-BUILD))

ifdef AKAMAKE-LINUX-BUILD-64
$P/configure.ts : $P/BUILDTARGET := akamai-linux-x86_64-alsi7$(strip $($P/OPENSSL_BUILDENV_NO_FOMIT_FRAME_POINTER_OPTION))
else # AKAMAKE-LINUX-BUILD-64
$P/configure.ts : $P/BUILDTARGET := akamai-linux-i686-alsi7$(strip $($P/OPENSSL_BUILDENV_NO_FOMIT_FRAME_POINTER_OPTION))
endif # AKAMAKE-LINUX-BUILD-64

else # ifdef AKAMAKE-ALSI7-BUILD/AKAMAKE-ALSI7-LITE-BUILD

ifneq (,$(AKAMAKE-ALSI8-BUILD)$(AKAMAKE-ALSI8-LITE-BUILD))

ifdef AKAMAKE-LINUX-BUILD-64
$P/configure.ts : $P/BUILDTARGET := akamai-linux-x86_64-alsi8$(strip $($P/OPENSSL_BUILDENV_NO_FOMIT_FRAME_POINTER_OPTION))
else # AKAMAKE-LINUX-BUILD-64
$P/configure.ts : $P/BUILDTARGET := akamai-linux-i686-alsi8$(strip $($P/OPENSSL_BUILDENV_NO_FOMIT_FRAME_POINTER_OPTION))
endif # AKAMAKE-LINUX-BUILD-64

else # ifdef AKAMAKE-ALSI8-BUILD/AKAMAKE-ALSI8-LITE-BUILD

ifneq (,$(AKAMAKE-ALSI9-BUILD)$(AKAMAKE-ALSI9-LITE-BUILD))

ifdef AKAMAKE-LINUX-BUILD-64
$P/configure.ts : $P/BUILDTARGET := akamai-linux-x86_64-alsi9$(strip $($P/OPENSSL_BUILDENV_NO_FOMIT_FRAME_POINTER_OPTION))
else # AKAMAKE-LINUX-BUILD-64
$P/configure.ts : $P/BUILDTARGET := akamai-linux-i686-alsi9$(strip $($P/OPENSSL_BUILDENV_NO_FOMIT_FRAME_POINTER_OPTION))
endif # AKAMAKE-LINUX-BUILD-64

else # ifdef AKAMAKE-ALSI9-BUILD/AKAMAKE-ALSI9-LITE-BUILD

ifdef AKAMAKE-DARWIN-BUILD

ifeq ($(KERNEL_BITS),64)
$P/configure.ts : $P/BUILDTARGET := darwin64-x86_64-cc
else # ifeq ($(KERNEL_BITS),64)
$P/configure.ts : $P/BUILDTARGET := darwin-i386-cc
endif # ifeq ($(KERNEL_BITS),64)

else # ifdef AKAMAKE-DARWIN-BUILD

ifdef AKAMAKE-WIN-BUILD

ifdef AKAMAKE-WIN64-BUILD
$P/configure.ts : $P/BUILDTARGET := VC-WIN64A no-asm
else # ifdef AKAMAKE-WIN64-BUILD
$P/configure.ts : $P/BUILDTARGET := VC-WIN32 no-asm
endif # ifdef AKAMAKE-WIN64-BUILD

endif # ifdef AKAMAKE-WIN-BUILD

endif # ifdef AKAMAKE-DARWIN-BUILD

# Mac OS X and Windows do not support the NO_FOMIT_FRAME_POINTER_OPTION

ifneq ($(strip $($P/OPENSSL_BUILDENV_NO_FOMIT_FRAME_POINTER_OPTION)),)
$(error ERROR: $P/OPENSSL_BUILDENV_NO_FOMIT_FRAME_POINTER not implemented on this architecture.)
endif # ifneq ($(strip $($P/OPENSSL_BUILDENV_NO_FOMIT_FRAME_POINTER_OPTION)),)

endif # ifdef AKAMAKE-ALSI9-BUILD/AKAMAKE-ALSI9-LITE-BUILD
endif # ifdef AKAMAKE-ALSI8-BUILD/AKAMAKE-ALSI8-LITE-BUILD
endif # ifdef AKAMAKE-ALSI7-BUILD/AKAMAKE-ALSI7-LITE-BUILD

ifneq ($(filter ccmalloc,$(MAKECMDGOALS)),)
$P/configure.ts : $P/CONFIGFLAGS := $($P/CONFIGFLAGS) -DPURIFY
endif # ifneq ($(filter ccmalloc,$(MAKECMDGOALS)),)

ifneq ($(filter debug,$(MAKECMDGOALS)),)
$P/configure.ts : $P/CONFIGFLAGS := $($P/CONFIGFLAGS) --debug
endif # ifneq ($(filter debug,$(MAKECMDGOALS)),)
