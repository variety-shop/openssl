#! /usr/bin/make -f

# FILE OFFSET BITS
$P/configure.ts : CONFIGFLAGS := $(CONFIGFLAGS)  $(filter %=64,-D_FILE_OFFSET_BITS=$(BUILDENV.FILE_OFFSET_BITS-master))

# CONFIGURE PROFILE: these are mutually-exclusive
ifeq ($(AKAMAKE-GCC-VERSION),3.3)
$P/configure.ts : CONFIGFLAGS := $(CONFIGFLAGS) akamai-linux-ppro-gcc33$(strip $($P/OPENSSL_BUILDENV_NO_FOMIT_FRAME_POINTER_OPTION))
else # ifeq ($(AKAMAKE-GCC-VERSION),3.3)

ifeq ($(AKAMAKE-GCC-VERSION),3.4)
$P/configure.ts : CONFIGFLAGS := $(CONFIGFLAGS) akamai-linux-ppro-gcc34$(strip $($P/OPENSSL_BUILDENV_NO_FOMIT_FRAME_POINTER_OPTION))
else # ifeq ($(AKAMAKE-GCC-VERSION),3.4)

ifeq ($(AKAMAKE-GCC-VERSION),4.0)
$P/configure.ts : CONFIGFLAGS := $(CONFIGFLAGS) akamai-linux-ppro-gcc40$(strip $($P/OPENSSL_BUILDENV_NO_FOMIT_FRAME_POINTER_OPTION))
else # ifeq ($(AKAMAKE-GCC-VERSION),4.0)

ifeq ($(AKAMAKE-GCC-VERSION),4.1)
# Note: alsi6 doesn't set AKAMAKE-GCC-VERSION
$P/configure.ts : CONFIGFLAGS := $(CONFIGFLAGS) akamai-linux-ppro-gcc41$(strip $($P/OPENSSL_BUILDENV_NO_FOMIT_FRAME_POINTER_OPTION))
else # ifeq ($(AKAMAKE-GCC-VERSION),4.1)

ifdef AKAMAKE-ALSI6-BUILD

ifdef AKAMAKE-LINUX-BUILD-64
$P/configure.ts : CONFIGFLAGS := $(CONFIGFLAGS) akamai-linux-x86_64-alsi6$(strip $($P/OPENSSL_BUILDENV_NO_FOMIT_FRAME_POINTER_OPTION))
else # AKAMAKE-LINUX-BUILD-64
$P/configure.ts : CONFIGFLAGS := $(CONFIGFLAGS) akamai-linux-ppro-alsi6$(strip $($P/OPENSSL_BUILDENV_NO_FOMIT_FRAME_POINTER_OPTION))
endif # AKAMAKE-LINUX-BUILD-64

else # ifdef AKAMAKE-ALSI6-BUILD

ifneq (,$(AKAMAKE-ALSI7-BUILD)$(AKAMAKE-ALSI7-LITE-BUILD))

ifdef AKAMAKE-LINUX-BUILD-64
$P/configure.ts : CONFIGFLAGS := $(CONFIGFLAGS) akamai-linux-x86_64-alsi7$(strip $($P/OPENSSL_BUILDENV_NO_FOMIT_FRAME_POINTER_OPTION))
else # AKAMAKE-LINUX-BUILD-64
$P/configure.ts : CONFIGFLAGS := $(CONFIGFLAGS) akamai-linux-i686-alsi7$(strip $($P/OPENSSL_BUILDENV_NO_FOMIT_FRAME_POINTER_OPTION))
endif # AKAMAKE-LINUX-BUILD-64

else # ifdef AKAMAKE-ALSI7-BUILD/AKAMAKE-ALSI7-LITE-BUILD

ifneq (,$(AKAMAKE-ALSI8-BUILD)$(AKAMAKE-ALSI8-LITE-BUILD))

ifdef AKAMAKE-LINUX-BUILD-64
$P/configure.ts : CONFIGFLAGS := $(CONFIGFLAGS) akamai-linux-x86_64-alsi8$(strip $($P/OPENSSL_BUILDENV_NO_FOMIT_FRAME_POINTER_OPTION))
else # AKAMAKE-LINUX-BUILD-64
$P/configure.ts : CONFIGFLAGS := $(CONFIGFLAGS) akamai-linux-i686-alsi8$(strip $($P/OPENSSL_BUILDENV_NO_FOMIT_FRAME_POINTER_OPTION))
endif # AKAMAKE-LINUX-BUILD-64

else # ifdef AKAMAKE-ALSI8-BUILD/AKAMAKE-ALSI8-LITE-BUILD

ifneq (,$(AKAMAKE-ALSI9-BUILD)$(AKAMAKE-ALSI9-LITE-BUILD))

ifdef AKAMAKE-LINUX-BUILD-64
$P/configure.ts : CONFIGFLAGS := $(CONFIGFLAGS) akamai-linux-x86_64-alsi9$(strip $($P/OPENSSL_BUILDENV_NO_FOMIT_FRAME_POINTER_OPTION))
else # AKAMAKE-LINUX-BUILD-64
$P/configure.ts : CONFIGFLAGS := $(CONFIGFLAGS) akamai-linux-i686-alsi9$(strip $($P/OPENSSL_BUILDENV_NO_FOMIT_FRAME_POINTER_OPTION))
endif # AKAMAKE-LINUX-BUILD-64

else # ifdef AKAMAKE-ALSI9-BUILD/AKAMAKE-ALSI9-LITE-BUILD

ifneq ($(filter ccmalloc,$(MAKECMDGOALS)),)
$P/configure.ts : CONFIGFLAGS := $(CONFIGFLAGS) akamai-ccmalloc
else # ifneq ($(filter ccmalloc,$(MAKECMDGOALS)),)

ifneq ($(filter debug,$(MAKECMDGOALS)),)
ifneq ($(filter osx-10.6,$(BUILDENV.OS)),)
$P/configure.ts : CONFIGFLAGS := $(CONFIGFLAGS) akamai-debug
else # ifneq ($(filter osx-10.6,$(BUILDENV.OS),)
ifeq ($(KERNEL_BITS),64)
$P/configure.ts : CONFIGFLAGS := $(CONFIGFLAGS) akamai-debug-darwin-x86_64
else # ifeq ($(KERNEL_BITS),64)
$P/configure.ts : CONFIGFLAGS := $(CONFIGFLAGS) akamai-debug-darwin-i386
endif # ifeq ($(KERNEL_BITS),64)
endif # ifneq ($(filter osx-10.6,$(BUILDENV.OS),)

else # ifneq ($(filter debug,$(MAKECMDGOALS)),)

ifneq ($(strip $($P/OPENSSL_BUILDENV_NO_FOMIT_FRAME_POINTER_OPTION)),)

$(error ERROR: $P/OPENSSL_BUILDENV_NO_FOMIT_FRAME_POINTER not implemented on this architecture.)

endif # ifneq ($(strip $($P/OPENSSL_BUILDENV_NO_FOMIT_FRAME_POINTER_OPTION)),)

endif # ifneq ($(filter debug,$(MAKECMDGOALS)),)
endif # ifneq ($(filter ccmalloc,$(MAKECMDGOALS)),)
endif # ifdef AKAMAKE-ALSI9-BUILD/AKAMAKE-ALSI9-LITE-BUILD
endif # ifdef AKAMAKE-ALSI8-BUILD/AKAMAKE-ALSI8-LITE-BUILD
endif # ifdef AKAMAKE-ALSI7-BUILD/AKAMAKE-ALSI7-LITE-BUILD
endif # ifdef AKAMAKE-ALSI6-BUILD
endif # ifeq ($(AKAMAKE-GCC-VERSION),4.1)
endif # ifeq ($(AKAMAKE-GCC-VERSION),4.0)
endif # ifeq ($(AKAMAKE-GCC-VERSION),3.4)
endif # ifeq ($(AKAMAKE-GCC-VERSION),3.3)
