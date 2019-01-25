#! /usr/bin/make -f

# FILE OFFSET BITS
$P/configure.ts : $P/CONFIGFLAGS := $($P/CONFIGFLAGS) $(filter %=64,-D_FILE_OFFSET_BITS=$(BUILDENV.FILE_OFFSET_BITS-master))

# CONFIGURE PROFILE: these are mutually-exclusive

ifneq (,$(AKAMAKE-ALSI7-BUILD)$(AKAMAKE-ALSI7-LITE-BUILD))

ifdef AKAMAKE-LINUX-BUILD-64
$P/configure.ts : $P/CONFIGFLAGS := $($P/CONFIGFLAGS) akamai-linux-x86_64-alsi7
else # AKAMAKE-LINUX-BUILD-64
$P/configure.ts : $P/CONFIGFLAGS := $($P/CONFIGFLAGS) akamai-linux-i686-alsi7
endif # AKAMAKE-LINUX-BUILD-64

else # ifdef AKAMAKE-ALSI7-BUILD/AKAMAKE-ALSI7-LITE-BUILD

ifneq (,$(AKAMAKE-ALSI8-BUILD)$(AKAMAKE-ALSI8-LITE-BUILD))

ifdef AKAMAKE-LINUX-BUILD-64
$P/configure.ts : $P/CONFIGFLAGS := $($P/CONFIGFLAGS) akamai-linux-x86_64-alsi8
else # AKAMAKE-LINUX-BUILD-64
$P/configure.ts : $P/CONFIGFLAGS := $($P/CONFIGFLAGS) akamai-linux-i686-alsi8
endif # AKAMAKE-LINUX-BUILD-64

else # ifdef AKAMAKE-ALSI8-BUILD/AKAMAKE-ALSI8-LITE-BUILD

ifneq (,$(AKAMAKE-ALSI9-BUILD)$(AKAMAKE-ALSI9-LITE-BUILD))

ifdef AKAMAKE-LINUX-BUILD-64
$P/configure.ts : $P/CONFIGFLAGS := $($P/CONFIGFLAGS) akamai-linux-x86_64-alsi9
else # AKAMAKE-LINUX-BUILD-64
$P/configure.ts : $P/CONFIGFLAGS := $($P/CONFIGFLAGS) akamai-linux-i686-alsi9
endif # AKAMAKE-LINUX-BUILD-64

else # ifdef AKAMAKE-ALSI9-BUILD/AKAMAKE-ALSI9-LITE-BUILD

ifneq (,$(AKAMAKE-ALSI10-BUILD)$(AKAMAKE-ALSI10-LITE-BUILD))

ifdef AKAMAKE-LINUX-BUILD-64
$P/configure.ts : $P/CONFIGFLAGS := $($P/CONFIGFLAGS) akamai-linux-x86_64-alsi10
else # AKAMAKE-LINUX-BUILD-64
$P/configure.ts : $P/CONFIGFLAGS := $($P/CONFIGFLAGS) akamai-linux-i686-alsi10
endif # AKAMAKE-LINUX-BUILD-64

else # ifdef AKAMAKE-ALSI10-BUILD/AKAMAKE-ALSI10-LITE-BUILD

ifdef AKAMAKE-DARWIN-BUILD

ifeq ($(KERNEL_BITS),64)
$P/configure.ts : $P/CONFIGFLAGS := $($P/CONFIGFLAGS) darwin64-x86_64-cc
else # ifeq ($(KERNEL_BITS),64)
$P/configure.ts : $P/CONFIGFLAGS := $($P/CONFIGFLAGS) darwin-i386-cc
endif # ifeq ($(KERNEL_BITS),64)

else # ifdef AKAMAKE-DARWIN-BUILD

ifdef AKAMAKE-WIN-BUILD

ifdef AKAMAKE-WIN64-BUILD
$P/configure.ts : $P/CONFIGFLAGS := $($P/CONFIGFLAGS) VC-WIN64A no-asm
else # ifdef AKAMAKE-WIN64-BUILD
$P/configure.ts : $P/CONFIGFLAGS := $($P/CONFIGFLAGS) VC-WIN32 no-asm
endif # ifdef AKAMAKE-WIN64-BUILD

endif # ifdef AKAMAKE-WIN-BUILD

endif # ifdef AKAMAKE-DARWIN-BUILD

endif # ifdef AKAMAKE-ALSI10-BUILD/AKAMAKE-ALSI10-LITE-BUILD
endif # ifdef AKAMAKE-ALSI9-BUILD/AKAMAKE-ALSI9-LITE-BUILD
endif # ifdef AKAMAKE-ALSI8-BUILD/AKAMAKE-ALSI8-LITE-BUILD
endif # ifdef AKAMAKE-ALSI7-BUILD/AKAMAKE-ALSI7-LITE-BUILD

ifneq ($(filter ccmalloc,$(MAKECMDGOALS)),)
$P/configure.ts : $P/CONFIGFLAGS := $($P/CONFIGFLAGS) -DPURIFY
endif # ifneq ($(filter ccmalloc,$(MAKECMDGOALS)),)

ifneq ($(filter debug,$(MAKECMDGOALS)),)
$P/configure.ts : $P/CONFIGFLAGS := $($P/CONFIGFLAGS) --debug
endif # ifneq ($(filter debug,$(MAKECMDGOALS)),)
