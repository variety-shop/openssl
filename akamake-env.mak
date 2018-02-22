#! /usr/bin/make -f

# FILE OFFSET BITS
$P/configure.ts : $P/CONFIGFLAGS := $($P/CONFIGFLAGS)  $(filter %=64,-D_FILE_OFFSET_BITS=$(BUILDENV.FILE_OFFSET_BITS-master))

ifdef AKAMAKE-ALSI6-BUILD

ifdef AKAMAKE-LINUX-BUILD-64
$P/configure.ts : $P/CONFIGFLAGS := $($P/CONFIGFLAGS) akamai-linux-x86_64-alsi6$(strip $($P/OPENSSL_BUILDENV_NO_FOMIT_FRAME_POINTER_OPTION))
else # AKAMAKE-LINUX-BUILD-64
$P/configure.ts : $P/CONFIGFLAGS := $($P/CONFIGFLAGS) akamai-linux-ppro-alsi6$(strip $($P/OPENSSL_BUILDENV_NO_FOMIT_FRAME_POINTER_OPTION))
endif # AKAMAKE-LINUX-BUILD-64

else # ifdef AKAMAKE-ALSI6-BUILD

ifneq (,$(AKAMAKE-ALSI7-BUILD)$(AKAMAKE-ALSI7-LITE-BUILD))

ifdef AKAMAKE-LINUX-BUILD-64
$P/configure.ts : $P/CONFIGFLAGS := $($P/CONFIGFLAGS) akamai-linux-x86_64-alsi7$(strip $($P/OPENSSL_BUILDENV_NO_FOMIT_FRAME_POINTER_OPTION))
else # AKAMAKE-LINUX-BUILD-64
$P/configure.ts : $P/CONFIGFLAGS := $($P/CONFIGFLAGS) akamai-linux-i686-alsi7$(strip $($P/OPENSSL_BUILDENV_NO_FOMIT_FRAME_POINTER_OPTION))
endif # AKAMAKE-LINUX-BUILD-64

else # ifdef AKAMAKE-ALSI7-BUILD/AKAMAKE-ALSI7-LITE-BUILD

ifneq (,$(AKAMAKE-ALSI8-BUILD)$(AKAMAKE-ALSI8-LITE-BUILD))

ifdef AKAMAKE-LINUX-BUILD-64
$P/configure.ts : $P/CONFIGFLAGS := $($P/CONFIGFLAGS) akamai-linux-x86_64-alsi8$(strip $($P/OPENSSL_BUILDENV_NO_FOMIT_FRAME_POINTER_OPTION))
else # AKAMAKE-LINUX-BUILD-64
$P/configure.ts : $P/CONFIGFLAGS := $($P/CONFIGFLAGS) akamai-linux-i686-alsi8$(strip $($P/OPENSSL_BUILDENV_NO_FOMIT_FRAME_POINTER_OPTION))
endif # AKAMAKE-LINUX-BUILD-64

else # ifdef AKAMAKE-ALSI8-BUILD/AKAMAKE-ALSI8-LITE-BUILD

ifneq (,$(AKAMAKE-ALSI9-BUILD)$(AKAMAKE-ALSI9-LITE-BUILD))

ifdef AKAMAKE-LINUX-BUILD-64
$P/configure.ts : $P/CONFIGFLAGS := $($P/CONFIGFLAGS) akamai-linux-x86_64-alsi9$(strip $($P/OPENSSL_BUILDENV_NO_FOMIT_FRAME_POINTER_OPTION))
else # AKAMAKE-LINUX-BUILD-64
$P/configure.ts : $P/CONFIGFLAGS := $($P/CONFIGFLAGS) akamai-linux-i686-alsi9$(strip $($P/OPENSSL_BUILDENV_NO_FOMIT_FRAME_POINTER_OPTION))
endif # AKAMAKE-LINUX-BUILD-64

else # ifdef AKAMAKE-ALSI9-BUILD/AKAMAKE-ALSI9-LITE-BUILD

ifneq ($(filter ccmalloc,$(MAKECMDGOALS)),)
$P/configure.ts : $P/CONFIGFLAGS := $($P/CONFIGFLAGS) akamai-ccmalloc
else # ifneq ($(filter ccmalloc,$(MAKECMDGOALS)),)

ifneq ($(filter debug,$(MAKECMDGOALS)),)
ifndef AKAMAKE-DARWIN-BUILD
$P/configure.ts : $P/CONFIGFLAGS := $($P/CONFIGFLAGS) akamai-debug
else # ifndef AKAMAKE-DARWIN-BUILD
ifeq ($(KERNEL_BITS),64)
$P/configure.ts : $P/CONFIGFLAGS := $($P/CONFIGFLAGS) akamai-debug-darwin-x86_64
else # ifeq ($(KERNEL_BITS),64)
$P/configure.ts : $P/CONFIGFLAGS := $($P/CONFIGFLAGS) akamai-debug-darwin-i386
endif # ifeq ($(KERNEL_BITS),64)
endif # ifndef AKAMAKE-DARWIN-BUILD

else # ifneq ($(filter debug,$(MAKECMDGOALS)),)

ifdef AKAMAKE-DARWIN-BUILD
ifeq ($(KERNEL_BITS),64)
$P/configure.ts : $P/CONFIGFLAGS := $($P/CONFIGFLAGS) darwin64-x86_64-cc
else # ifeq ($(KERNEL_BITS),64)
$P/configure.ts : $P/CONFIGFLAGS := $($P/CONFIGFLAGS) darwin-i386-cc
endif # ifeq ($(KERNEL_BITS),64)
endif # ifdef AKAMAKE-DARWIN-BUILD

ifneq ($(strip $($P/OPENSSL_BUILDENV_NO_FOMIT_FRAME_POINTER_OPTION)),)

$(error ERROR: $P/OPENSSL_BUILDENV_NO_FOMIT_FRAME_POINTER not implemented on this architecture.)

endif # ifneq ($(strip $($P/OPENSSL_BUILDENV_NO_FOMIT_FRAME_POINTER_OPTION)),)

endif # ifneq ($(filter debug,$(MAKECMDGOALS)),)
endif # ifneq ($(filter ccmalloc,$(MAKECMDGOALS)),)
endif # ifdef AKAMAKE-ALSI9-BUILD/AKAMAKE-ALSI9-LITE-BUILD
endif # ifdef AKAMAKE-ALSI8-BUILD/AKAMAKE-ALSI8-LITE-BUILD
endif # ifdef AKAMAKE-ALSI7-BUILD/AKAMAKE-ALSI7-LITE-BUILD
endif # ifdef AKAMAKE-ALSI6-BUILD
