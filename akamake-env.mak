#! /usr/bin/make -f

# FILE OFFSET BITS
$P/configure.ts : CFLAGS += $(filter %=64,-D_FILE_OFFSET_BITS=$(BUILDENV.FILE_OFFSET_BITS-master))

# CONFIGURE PROFILE: these are mutually-exclusive

ifeq ($(BUILDENV.OS),btf-anaconda)
$P/configure.ts : $P/BUILDTARGET := btf-anaconda
else ifdef AKAMAKE-LINUX-BUILD-64
$P/configure.ts : $P/BUILDTARGET := akamai-alsi-x86_64
else ifdef AKAMAKE-LINUX-BUILD-32
$P/configure.ts : $P/BUILDTARGET := akamai-alsi-x86
else ifdef AKAMAKE-DARWIN-BUILD-64
$P/configure.ts : $P/BUILDTARGET := darwin64-x86_64-cc
else ifdef AKAMAKE-DARWIN-BUILD-32
$P/configure.ts : $P/BUILDTARGET := darwin-i386-cc
else # ifdef AKAMAKE-*-BUILD-*
$(error Unsupported or unknown build target)
endif # ifdef AKAMAKE-*-BUILD-*

ifneq ($(filter ccmalloc,$(MAKECMDGOALS)),)
$P/configure.ts : CFLAGS += -DPURIFY
endif # ifneq ($(filter ccmalloc,$(MAKECMDGOALS)),)

ifneq ($(filter debug,$(MAKECMDGOALS)),)
$P/configure.ts : $P/SHAREDFEATURES := $($P/SHAREDFEATURES) --debug
$P/configure.ts : $P/CONFIGFEATURES := $($P/CONFIGFEATURES) --debug
endif # ifneq ($(filter debug,$(MAKECMDGOALS)),)
