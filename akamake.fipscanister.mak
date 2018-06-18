# included for fipscanister support

ifdef FIPSBUILD
# Include fipscanister build variables.
-include $(call get-component-path,fipscanister)/enable_fips_with_akamai_openssl.mk

$P/DEP-COMPS := $($P/DEP-COMPS) fipscanister
$P/NOSHARED := $($P/NOSHARED) fips

#### fipscanister has all the modules precompiled due to compliance reasons, so ####
#### we'll have to specify which one we'll want to use here, this is the same   ####
#### environment detection used in the fipscanister akamake                     ####

# [jhorsfal 03/09/2017] Updates for GCDS, Removed OS selection code, this should all
# come from fipscanister variables.

# OS Specific FIPS lib directory
$P/FIPS_LIBDIR = $($(call get-component-path,fipscanister)/FIPS_LIBDIR)
# OS Specific FIPS root
$P/CURRENT_OS_FIPS_DIR = $($(call get-component-path,fipscanister)/FIPSDIR)
# FIPS Linker
$P/FIPSLD = $($(call get-component-path,fipscanister)/FIPSLD)
# FIPS build target
$P/FIPS_BUILD_TARGET = $(call get-component-path,fipscanister)/akamake.auto_os.ts
# FIPS requires their own linker to build correctly so we're doing that here
# sverasch 7/24/14
$P/OPENSSL-CC = CC="$($P/FIPSLD)" FIPSLD_CC="$(CC)"
# Assert minnimum fips version
$(call assert_min_version,fipscanister,2.0.13)

$P/% : FIPSFLAGS = fips --with-fipsdir=$($P/CURRENT_OS_FIPS_DIR) --with-fipslibdir=$($P/FIPS_LIBDIR)

$P/buildenv.FIPS: $($P/FIPS_BUILD_TARGET)
	echo "FIPS canister build enabled" > $P/buildenv.FIPS

else # ifdef FIPSBUILD

$P/% : FIPSFLAGS =
$P/buildenv.FIPS:
	echo "FIPS canister build disabled" > $P/buildenv.FIPS

endif # ifdef FIPSBUILD
