#!/usr/local/bin/perl
# A bit of an evil hack but it post processes the file ../MINFO which
# is generated by `make files` in the top directory.
# This script outputs one mega makefile that has no shell stuff or any
# funny stuff (if the target is not "copy").
# If the target is "copy", then it tries to create a makefile that can be
# safely used with the -j flag and that is compatible with the top-level
# Makefile, in the sense that it uses the same options and assembler files etc.

use Cwd;

$INSTALLTOP="/usr/local/ssl";
$OPENSSLDIR="/usr/local/ssl";
$OPTIONS="";
$ssl_version="";
$banner="\t\@echo Building OpenSSL";

my $no_static_engine = 1;
my $engines = "";
my $otherlibs = "";
local $zlib_opt = 0;	# 0 = no zlib, 1 = static, 2 = dynamic
local $zlib_lib = "";
local $perl_asm = 0;	# 1 to autobuild asm files from perl scripts

my $ex_l_libs = "";

# Options to import from top level Makefile

my %mf_import = (
	VERSION	       => \$ssl_version,
	OPTIONS        => \$OPTIONS,
	INSTALLTOP     => \$INSTALLTOP,
	OPENSSLDIR     => \$OPENSSLDIR,
	PLATFORM       => \$mf_platform,
	CC             => \$mf_cc,
	CFLAG	       => \$mf_cflag,
	DEPFLAG	       => \$mf_depflag,
	CPUID_OBJ      => \$mf_cpuid_asm,
	BN_ASM	       => \$mf_bn_asm,
	DES_ENC	       => \$mf_des_asm,
	AES_ENC        => \$mf_aes_asm,
	BF_ENC	       => \$mf_bf_asm,
	CAST_ENC       => \$mf_cast_asm,
	RC4_ENC	       => \$mf_rc4_asm,
	RC5_ENC        => \$mf_rc5_asm,
	MD5_ASM_OBJ    => \$mf_md5_asm,
	SHA1_ASM_OBJ   => \$mf_sha_asm,
	RMD160_ASM_OBJ => \$mf_rmd_asm,
	WP_ASM_OBJ     => \$mf_wp_asm,
	CMLL_ENC       => \$mf_cm_asm,
	MODES_ASM_OBJ  => \$mf_modes_asm,
        ENGINES_ASM_OBJ=> \$mf_engines_asm,
	BASEADDR       => \$baseaddr,
	FIPSDIR        => \$fipsdir,
	EC_ASM	       => \$mf_ec_asm,
);

open(IN,"<Makefile") || die "unable to open Makefile!\n";
while(<IN>) {
    my ($mf_opt, $mf_ref);
    while (($mf_opt, $mf_ref) = each %mf_import) {
    	if (/^$mf_opt\s*=\s*(.*)$/ && !defined($$mfref)) {
	   $$mf_ref = $1;
	}
    }
}
close(IN);

$debug = 1 if $mf_platform =~ /^debug-/;

die "Makefile is not the toplevel Makefile!\n" if $ssl_version eq "";

$infile="MINFO";

%ops=(
	"VC-WIN32",   "Microsoft Visual C++ [4-6] - Windows NT or 9X",
	"akamai-VC-WIN32",   "Microsoft Visual C++ [4-6] - Windows NT or 9X",
	"VC-WIN64I",  "Microsoft C/C++ - Win64/IA-64",
	"VC-WIN64A",  "Microsoft C/C++ - Win64/x64",
	"akamai-VC-WIN64A",  "Microsoft C/C++ - Win64/x64",
	"VC-CE",   "Microsoft eMbedded Visual C++ 3.0 - Windows CE ONLY",
	"VC-NT",   "Microsoft Visual C++ [4-6] - Windows NT ONLY",
	"VC-NT-VC7",  "Microsoft Visual C++ [4-6] - Windows NT ONLY",
	"VC-NT-VC9",  "Microsoft Visual C++ [4-6] - Windows NT ONLY",
	"VC-NT-VC10", "Microsoft Visual C++ [4-6] - Windows NT ONLY",
	"Mingw32", "GNU C++ - Windows NT or 9x",
	"Mingw32-files", "Create files with DOS copy ...",
	"BC-NT",   "Borland C++ 4.5 - Windows NT",
	"linux-elf","Linux elf",
	"ultrix-mips","DEC mips ultrix",
	"FreeBSD","FreeBSD distribution",
	"OS2-EMX", "EMX GCC OS/2",
	"netware-clib", "CodeWarrior for NetWare - CLib - with WinSock Sockets",
	"netware-clib-bsdsock", "CodeWarrior for NetWare - CLib - with BSD Sockets",
	"netware-libc", "CodeWarrior for NetWare - LibC - with WinSock Sockets",
	"netware-libc-bsdsock", "CodeWarrior for NetWare - LibC - with BSD Sockets",
	"default","cc under unix",
	"auto", "auto detect from top level Makefile",
        "copy", "copy from top level Makefile"
	);

$platform="";
my $xcflags="";
foreach (@ARGV)
	{
        next if /^[ ]*$/; # Akamai
	if (!&read_options && !defined($ops{$_}))
		{
		#Akamai print STDERR "unknown option - $_\n";
		print STDERR "unknown option - \"$_\"\n";
		print STDERR "usage: perl mk1mf.pl [options] [system]\n";
		print STDERR "\nwhere [system] can be one of the following\n";
		foreach $i (sort keys %ops)
		{ printf STDERR "\t%-10s\t%s\n",$i,$ops{$i}; }
		print STDERR <<"EOF";
and [options] can be one of
	no-md2 no-md4 no-md5 no-sha no-mdc2	- Skip this digest
	no-ripemd
	no-rc2 no-rc4 no-rc5 no-idea no-des     - Skip this symetric cipher
	no-bf no-cast no-aes no-camellia no-seed
	no-rsa no-dsa no-dh			- Skip this public key cipher
	no-ssl2 no-ssl3	no-tls1 no-dtls1	- Skip this version of SSL
	just-ssl				- remove all non-ssl keys/digest
	no-asm 					- No x86 asm
	no-krb5					- No KRB5
	no-srp					- No SRP
	no-ec					- No EC
	no-ecdsa				- No ECDSA
	no-ecdh					- No ECDH
	no-engine				- No engine
	no-hw					- No hw
	nasm 					- Use NASM for x86 asm
	nw-nasm					- Use NASM x86 asm for NetWare
	nw-mwasm				- Use Metrowerks x86 asm for NetWare
	gaswin					- Use GNU as with Mingw32
	no-socks				- No socket code
	no-err					- No error strings
	dll/shlib/dll_lib			- Build shared libraries (MS)
	debug					- Debug build
        profile                                 - Profiling build
	gcc					- Use Gcc (unix)

Values that can be set
TMP=tmpdir OUT=outdir SRC=srcdir BIN=binpath INC=header-outdir CC=C-compiler

-L<ex_lib_path> -l<ex_lib>			- extra library flags (unix)
-<ex_cc_flags>					- extra 'cc' flags,
						  added (MS), or replace (unix)
EOF
		exit(1);
		}
	$platform=$_;
	}
foreach (grep(!/^$/, split(/ /, $OPTIONS)))
	{
	print STDERR "unknown option - $_\n" if !&read_options;
	}

$no_static_engine = 0 if (!$shlib);

$no_mdc2=1 if ($no_des);

$no_tls1=1 if ($no_md5 || $no_sha);
$no_tls1=1 if ($no_rsa && $no_dh);

$no_ssl3=1 if ($no_md5 || $no_sha);
$no_ssl3=1 if ($no_rsa && $no_dh);

$no_ssl2=1 if ($no_md5);
$no_ssl2=1 if ($no_rsa);

$out_def="out";
$inc_def="outinc";
$tmp_def="tmp";

$perl="perl" unless defined $perl;
$mkdir="-mkdir" unless defined $mkdir;

($ssl,$crypto)=("ssl","crypto");
$ranlib="echo ranlib";

$cc=(defined($VARS{'CC'}))?$VARS{'CC'}:'cc';
$src_dir=(defined($VARS{'SRC'}))?$VARS{'SRC'}: $platform eq 'copy' ? getcwd() : '.';
$bin_dir=(defined($VARS{'BIN'}))?$VARS{'BIN'}:'';

# $bin_dir.=$o causes a core dump on my sparc :-(


$NT=0;

push(@INC,"util/pl","pl");

if ($platform eq "auto" || $platform eq 'copy') {
	$orig_platform = $platform;
	$platform = $mf_platform;
	print STDERR "Imported platform $mf_platform\n";
}

if (($platform =~ /VC-(.+)/))
	{
	$FLAVOR=$1;
	$NT = 1 if $1 eq "NT";
#Akamai	require 'VC-32.pl';
	require 'aka-VC-32.pl';
	}
elsif ($platform eq "Mingw32")
	{
	require 'Mingw32.pl';
	}
elsif ($platform eq "Mingw32-files")
	{
	require 'Mingw32f.pl';
	}
elsif ($platform eq "BC-NT")
	{
	$bc=1;
	require 'BC-32.pl';
	}
elsif ($platform eq "FreeBSD")
	{
	require 'unix.pl';
	$cflags='-DTERMIO -D_ANSI_SOURCE -O2 -fomit-frame-pointer';
	}
elsif ($platform eq "linux-elf")
	{
	require "unix.pl";
	require "linux.pl";
	$unix=1;
	}
elsif ($platform eq "ultrix-mips")
	{
	require "unix.pl";
	require "ultrix.pl";
	$unix=1;
	}
elsif ($platform eq "OS2-EMX")
	{
	$wc=1;
	require 'OS2-EMX.pl';
	}
elsif (($platform eq "netware-clib") || ($platform eq "netware-libc") ||
       ($platform eq "netware-clib-bsdsock") || ($platform eq "netware-libc-bsdsock"))
	{
	$LIBC=1 if $platform eq "netware-libc" || $platform eq "netware-libc-bsdsock";
	$BSDSOCK=1 if ($platform eq "netware-libc-bsdsock") || ($platform eq "netware-clib-bsdsock");
	require 'netware.pl';
	}
else
	{
	require "unix.pl";

	$unix=1;
	$cflags.=' -DTERMIO';
	}

$fipsdir =~ s/\//${o}/g;

# Akamai $out_dir=(defined($VARS{'OUT'}))?$VARS{'OUT'}:$out_def.($debug?".dbg":"");
# Akamai $tmp_dir=(defined($VARS{'TMP'}))?$VARS{'TMP'}:$tmp_def.($debug?".dbg":"");
$out_dir=(defined($VARS{'OUT'}))?$VARS{'OUT'}:$out_def;
$tmp_dir=(defined($VARS{'TMP'}))?$VARS{'TMP'}:$tmp_def;
$inc_dir=(defined($VARS{'INC'}))?$VARS{'INC'}:$inc_def;

$bin_dir=$bin_dir.$o unless ((substr($bin_dir,-1,1) eq $o) || ($bin_dir eq ''));

$cflags= "$xcflags$cflags" if $xcflags ne "";

$cflags.=" -DOPENSSL_NO_IDEA" if $no_idea;
$cflags.=" -DOPENSSL_NO_AES"  if $no_aes;
$cflags.=" -DOPENSSL_NO_CAMELLIA"  if $no_camellia;
$cflags.=" -DOPENSSL_NO_SEED" if $no_seed;
$cflags.=" -DOPENSSL_NO_RC2"  if $no_rc2;
$cflags.=" -DOPENSSL_NO_RC4"  if $no_rc4;
$cflags.=" -DOPENSSL_NO_RC5"  if $no_rc5;
$cflags.=" -DOPENSSL_NO_MD2"  if $no_md2;
$cflags.=" -DOPENSSL_NO_MD4"  if $no_md4;
$cflags.=" -DOPENSSL_NO_MD5"  if $no_md5;
$cflags.=" -DOPENSSL_NO_SHA"  if $no_sha;
$cflags.=" -DOPENSSL_NO_SHA1" if $no_sha1;
$cflags.=" -DOPENSSL_NO_RIPEMD" if $no_ripemd;
$cflags.=" -DOPENSSL_NO_MDC2" if $no_mdc2;
$cflags.=" -DOPENSSL_NO_BF"  if $no_bf;
$cflags.=" -DOPENSSL_NO_CAST" if $no_cast;
$cflags.=" -DOPENSSL_NO_DES"  if $no_des;
$cflags.=" -DOPENSSL_NO_RSA"  if $no_rsa;
$cflags.=" -DOPENSSL_NO_DSA"  if $no_dsa;
$cflags.=" -DOPENSSL_NO_DH"   if $no_dh;
$cflags.=" -DOPENSSL_NO_WHIRLPOOL"   if $no_whirlpool;
$cflags.=" -DOPENSSL_NO_SOCK" if $no_sock;
$cflags.=" -DOPENSSL_NO_SSL2" if $no_ssl2;
$cflags.=" -DOPENSSL_NO_SSL3" if $no_ssl3;
$cflags.=" -DOPENSSL_NO_TLS1" if $no_tls1;
$cflags.=" -DOPENSSL_NO_DTLS1" if $no_dtls1;
$cflags.=" -DOPENSSL_NO_TLSEXT" if $no_tlsext;
$cflags.=" -DOPENSSL_NO_TLS1" if $no_tls1;
$cflags.=" -DOPENSSL_NO_SRP" if $no_srp;
$cflags.=" -DOPENSSL_NO_CMS" if $no_cms;
$cflags.=" -DOPENSSL_NO_ERR"  if $no_err;
$cflags.=" -DOPENSSL_NO_KRB5" if $no_krb5;
$cflags.=" -DOPENSSL_NO_EC"   if $no_ec;
$cflags.=" -DOPENSSL_NO_ECDSA" if $no_ecdsa;
$cflags.=" -DOPENSSL_NO_ECDH" if $no_ecdh;
$cflags.=" -DOPENSSL_NO_GOST" if $no_gost;
$cflags.=" -DOPENSSL_NO_ENGINE"   if $no_engine;
$cflags.=" -DOPENSSL_NO_HW"   if $no_hw;
$cflags.=" -DOPENSSL_FIPS"    if $fips;
$cflags.=" -DOPENSSL_NO_JPAKE"    if $no_jpake;
$cflags.=" -DOPENSSL_NO_EC2M"    if $no_ec2m;
$cflags.=" -DOPENSSL_NO_WEAK_SSL_CIPHERS"   if $no_weak_ssl;
$cflags.=" -DOPENSSL_NO_BUF_FREELISTS" if $no_buf_freelists;
$cflags.=" -DOPENSSL_NO_HEARTBEATS" if $no_heartbeats;
$cflags.=" -DOPENSSL_NO_AKAMAI_ASYNC_RSALG" if $no_akamai_async_rsalg; #Akamai
$cflags.=" -DOPENSSL_NO_AKAMAI_GHOST_HIGH" if $no_akamai_ghost_high; #Akamai
$cflags.=" -DOPENSSL_NO_AKAMAI_CLIENT_CACHE" if $no_akamai_client_cache; #Akamai
$cflags.=" -DOPENSSL_PSK" if $no_psk;
$cflags.=" -DZLIB" if $zlib_opt;
$cflags.=" -DZLIB_SHARED" if $zlib_opt == 2;
$cflags.=" -DOPENSSL_NO_COMP" if $no_comp;

if ($no_static_engine)
	{
	$cflags .= " -DOPENSSL_NO_STATIC_ENGINE";
	}
else
	{
	$cflags .= " -DOPENSSL_NO_DYNAMIC_ENGINE";
	}

#$cflags.=" -DRSAref"  if $rsaref ne "";

## if ($unix)
##	{ $cflags="$c_flags" if ($c_flags ne ""); }
##else
	{ $cflags="$c_flags$cflags" if ($c_flags ne ""); }

if ($orig_platform eq 'copy') {
    $cflags = $mf_cflag;
    $cc = $mf_cc;
}

$ex_libs="$l_flags$ex_libs" if ($l_flags ne "");


%shlib_ex_cflags=("SSL" => " -DOPENSSL_BUILD_SHLIBSSL",
		  "CRYPTO" => " -DOPENSSL_BUILD_SHLIBCRYPTO");

if ($msdos)
	{
	$banner ="\t\@echo Make sure you have run 'perl Configure $platform' in the\n";
	$banner.="\t\@echo top level directory, if you don't have perl, you will\n";
	$banner.="\t\@echo need to probably edit crypto/bn/bn.h, check the\n";
	$banner.="\t\@echo documentation for details.\n";
	}

# have to do this to allow $(CC) under unix
$link="$bin_dir$link" if ($link !~ /^\$/);

$INSTALLTOP =~ s|/|$o|g;
$OPENSSLDIR =~ s|/|$o|g;

#############################################
# We parse in input file and 'store' info for later printing.
open(IN,"<$infile") || die "unable to open $infile:$!\n";
$_=<IN>;
for (;;)
	{
	s/\s*$//; # was chop, didn't work in mixture of perls for Windows...

	($key,$val)=/^([^=]+)=(.*)/;
	if ($key eq "RELATIVE_DIRECTORY")
		{
		if ($lib ne "")
			{
			$uc=$lib;
			$uc =~ s/^lib(.*)\.a/$1/;
			$uc =~ tr/a-z/A-Z/;
			$lib_nam{$uc}=$uc;
			$lib_obj{$uc}.=$libobj." ";
			}
		last if ($val eq "FINISHED");
		$lib="";
		$libobj="";
		$dir=$val;
		}

	if ($key eq "KRB5_INCLUDES")
		{ $cflags .= " $val";}

	if ($key eq "ZLIB_INCLUDE")
		{ $cflags .= " $val" if $val ne "";}

	if ($key eq "LIBZLIB")
		{ $zlib_lib = "$val" if $val ne "";}

	if ($key eq "LIBKRB5")
		{ $ex_libs .= " $val" if $val ne "";}

	if ($key eq "TEST")
		{ $test.=&var_add($dir,$val, 0); }

	if (($key eq "PROGS") || ($key eq "E_OBJ"))
		{ $e_exe.=&var_add($dir,$val, 0); }

	if ($key eq "LIB")
		{
		$lib=$val;
		$lib =~ s/^.*\/([^\/]+)$/$1/;
		}
	if ($key eq "LIBNAME" && $no_static_engine)
		{
		$lib=$val;
		$lib =~ s/^.*\/([^\/]+)$/$1/;
		$otherlibs .= " $lib";
		}

	if ($key eq "EXHEADER")
		{ $exheader.=&var_add($dir,$val, 1); }

	if ($key eq "HEADER")
		{ $header.=&var_add($dir,$val, 1); }

	if ($key eq "LIBOBJ" && ($dir ne "engines" || !$no_static_engine))
		{ $libobj=&var_add($dir,$val, 0); }
	if ($key eq "LIBNAMES" && $dir eq "engines" && $no_static_engine)
 		{ $engines.=$val }

	if (!($_=<IN>))
		{ $_="RELATIVE_DIRECTORY=FINISHED\n"; }
	}
close(IN);

if ($orig_platform eq 'copy')
	{
	# Remove opensslconf.h so it doesn't get updated if we configure a
	# different branch.
	$exheader =~ s/[^ ]+\/opensslconf.h//;
	$header =~ s/[^ ]+\/opensslconf.h//;
	}

if ($shlib)
	{
	$extra_install= <<"EOF";
	\$(CP) \"\$(O_SSL)\" \"\$(INSTALLTOP)${o}bin\"
	\$(CP) \"\$(O_CRYPTO)\" \"\$(INSTALLTOP)${o}bin\"
	\$(CP) \"\$(L_SSL)\" \"\$(INSTALLTOP)${o}lib\"
	\$(CP) \"\$(L_CRYPTO)\" \"\$(INSTALLTOP)${o}lib\"
EOF
	if ($no_static_engine)
		{
		$extra_install .= <<"EOF"
	\$(MKDIR) \"\$(INSTALLTOP)${o}lib${o}engines\"
	\$(CP) \"\$(E_SHLIB)\" \"\$(INSTALLTOP)${o}lib${o}engines\"
EOF
		}
	}
else
	{
	$extra_install= <<"EOF";
	\$(CP) \"\$(O_SSL)\" \"\$(INSTALLTOP)${o}lib\"
	\$(CP) \"\$(O_CRYPTO)\" \"\$(INSTALLTOP)${o}lib\"
EOF
	$ex_libs .= " $zlib_lib" if $zlib_opt == 1;
	if ($fips)
		{
		$build_targets .= " \$(LIB_D)$o$crypto_compat \$(PREMAIN_DSO_EXE)";
		$ex_l_libs .= " \$(O_FIPSCANISTER)";
		}
	}

$defs= <<"EOF";
# N.B. You MUST use -j on FreeBSD.
# This makefile has been automatically generated from the OpenSSL distribution.
# This single makefile will build the complete OpenSSL distribution and
# by default leave the 'interesting' output files in .${o}out and the stuff
# that needs deleting in .${o}tmp.
# The file was generated by running 'make makefile.one', which
# does a 'make files', which writes all the environment variables from all
# the makefiles to the file call MINFO.  This file is used by
# util${o}mk1mf.pl to generate makefile.one.
# The 'makefile per directory' system suites me when developing this
# library and also so I can 'distribute' indervidual library sections.
# The one monster makefile better suits building in non-unix
# environments.

EOF

$defs .= $preamble if defined $preamble;

$defs.= <<"EOF";
INSTALLTOP=$INSTALLTOP
OPENSSLDIR=$OPENSSLDIR

# Set your compiler options
PLATFORM=$platform
CC=$bin_dir${cc}
CFLAG=$cflags
APP_CFLAG=$app_cflag
LIB_CFLAG=$lib_cflag
SHLIB_CFLAG=$shl_cflag
APP_EX_OBJ=$app_ex_obj
SHLIB_EX_OBJ=$shlib_ex_obj
# add extra libraries to this define, for solaris -lsocket -lnsl would
# be added
EX_LIBS=$ex_libs

# The OpenSSL directory
SRC_D=$src_dir

LINK_CMD=$link
LFLAGS=$lflags
RSC=$rsc

# The output directory for everything interesting
OUT_D=$out_dir
# The output directory for all the temporary muck
TMP_D=$tmp_dir
# The output directory for the header files
INC_D=$inc_dir
INCO_D=$inc_dir${o}openssl

PERL=$perl
CP=$cp
RM=$rm
RANLIB=$ranlib
MKDIR=$mkdir
MKLIB=$bin_dir$mklib
MLFLAGS=$mlflags
ASM=$bin_dir$asm

# FIPS validated module and support file locations

E_PREMAIN_DSO=fips_premain_dso

FIPSDIR=$fipsdir
BASEADDR=$baseaddr
FIPSLIB_D=\$(FIPSDIR)${o}lib
FIPS_PREMAIN_SRC=\$(FIPSLIB_D)${o}fips_premain.c
O_FIPSCANISTER=\$(FIPSLIB_D)${o}fipscanister.lib
FIPS_SHA1_EXE=\$(FIPSDIR)${o}bin${o}fips_standalone_sha1${exep}
PREMAIN_DSO_EXE=\$(BIN_D)${o}fips_premain_dso$exep
FIPSLINK=\$(PERL) \$(FIPSDIR)${o}bin${o}fipslink.pl

######################################################
# You should not need to touch anything below this point
######################################################

E_EXE=openssl
SSL=$ssl
CRYPTO=$crypto

# BIN_D  - Binary output directory
# TEST_D - Binary test file output directory
# LIB_D  - library output directory
# ENG_D  - dynamic engine output directory
# Note: if you change these point to different directories then uncomment out
# the lines around the 'NB' comment below.
# 
BIN_D=\$(OUT_D)
TEST_D=\$(OUT_D)
LIB_D=\$(OUT_D)
ENG_D=\$(OUT_D)

# INCL_D - local library directory
# OBJ_D  - temp object file directory
OBJ_D=\$(TMP_D)
INCL_D=\$(TMP_D)

O_SSL=     \$(LIB_D)$o$plib\$(SSL)$shlibp
O_CRYPTO=  \$(LIB_D)$o$plib\$(CRYPTO)$shlibp
SO_SSL=    $plib\$(SSL)$so_shlibp
SO_CRYPTO= $plib\$(CRYPTO)$so_shlibp
L_SSL=     \$(LIB_D)$o$plib\$(SSL)$libp
L_CRYPTO=  \$(LIB_D)$o$plib\$(CRYPTO)$libp

L_LIBS= \$(L_SSL) \$(L_CRYPTO) $ex_l_libs

######################################################
# Don't touch anything below this point
######################################################

#Akamai INC=-I\$(INC_D) -I\$(INCL_D)
INC=-I\$(INC_D) -I\$(INCL_D) -I.
APP_CFLAGS=\$(INC) \$(CFLAG) \$(APP_CFLAG)
LIB_CFLAGS=\$(INC) \$(CFLAG) \$(LIB_CFLAG)
SHLIB_CFLAGS=\$(INC) \$(CFLAG) \$(LIB_CFLAG) \$(SHLIB_CFLAG)
LIBS_DEP=\$(O_CRYPTO) \$(O_SSL)

#############################################
EOF

$rules=<<"EOF";
all: banner \$(TMP_D) \$(BIN_D) \$(TEST_D) \$(LIB_D) \$(INCO_D) headers lib exe $build_targets

banner:
$banner

\$(TMP_D):
	\$(MKDIR) \"\$(TMP_D)\"
# NB: uncomment out these lines if BIN_D, TEST_D and LIB_D are different
#\$(BIN_D):
#	\$(MKDIR) \$(BIN_D)
#
#\$(TEST_D):
#	\$(MKDIR) \$(TEST_D)

\$(LIB_D):
	\$(MKDIR) \"\$(LIB_D)\"

\$(INCO_D): \$(INC_D)
	\$(MKDIR) \"\$(INCO_D)\"

\$(INC_D):
	\$(MKDIR) \"\$(INC_D)\"

# This needs to be invoked once, when the makefile is first constructed, or
# after cleaning.
init: \$(TMP_D) \$(LIB_D) \$(INC_D) \$(INCO_D) \$(BIN_D) \$(TEST_D) headers
	\$(PERL) \$(SRC_D)/util/copy-if-different.pl "\$(SRC_D)/crypto/opensslconf.h" "\$(INCO_D)/opensslconf.h"

#Akamai headers: \$(HEADER) \$(EXHEADER)
\$(SRC_D)\\crypto\\bn\\bn_prime.h : \$(SRC_D)\\crypto\\bn\\bn_prime.pl
	\$(PERL) \$? > \$@

headers: \$(TMP_D) \$(INCO_D) \$(HEADER) \$(EXHEADER) \$(SRC_D)\\crypto\\bn\\bn_prime.h

lib: \$(LIBS_DEP) \$(E_SHLIB)

exe: \$(T_EXE) \$(BIN_D)$o\$(E_EXE)$exep

install: all
	\$(MKDIR) \"\$(INSTALLTOP)\"
	\$(MKDIR) \"\$(INSTALLTOP)${o}bin\"
	\$(MKDIR) \"\$(INSTALLTOP)${o}include\"
	\$(MKDIR) \"\$(INSTALLTOP)${o}include${o}openssl\"
	\$(MKDIR) \"\$(INSTALLTOP)${o}lib\"
	\$(CP) \"\$(INCO_D)${o}*.\[ch\]\" \"\$(INSTALLTOP)${o}include${o}openssl\"
	\$(CP) \"\$(BIN_D)$o\$(E_EXE)$exep \$(INSTALLTOP)${o}bin\"
	\$(MKDIR) \"\$(OPENSSLDIR)\"
	\$(CP) apps${o}openssl.cnf \"\$(OPENSSLDIR)\"
$extra_install

clean:
	\$(RM) \$(TMP_D)$o*.*

vclean:
	\$(RM) \$(TMP_D)$o*.*
	\$(RM) \$(OUT_D)$o*.*

reallyclean:
	\$(RM) -rf \$(TMP_D)
	\$(RM) -rf \$(BIN_D)
	\$(RM) -rf \$(TEST_D)
	\$(RM) -rf \$(LIB_D)
	\$(RM) -rf \$(INC_D)

EOF

if ($orig_platform ne 'copy')
	{
        $rules .= <<"EOF";
test: \$(T_EXE)
	cd \$(BIN_D)
	..${o}ms${o}test

EOF
	}

my $platform_cpp_symbol = "MK1MF_PLATFORM_$platform";
$platform_cpp_symbol =~ s/-/_/g;
if (open(IN,"crypto/buildinf.h"))
	{
	# Remove entry for this platform in existing file buildinf.h.

	my $old_buildinf_h = "";
	while (<IN>)
		{
		if (/^\#ifdef $platform_cpp_symbol$/)
			{
			while (<IN>) { last if (/^\#endif/); }
			}
		else
			{
			$old_buildinf_h .= $_;
			}
		}
	close(IN);

	open(OUT,">crypto/buildinf.h") || die "Can't open buildinf.h";
	print OUT $old_buildinf_h;
	close(OUT);
	}

open (OUT,">>crypto/buildinf.h") || die "Can't open buildinf.h";
printf OUT <<EOF;
#ifdef $platform_cpp_symbol
  /* auto-generated/updated by util/mk1mf.pl for crypto/cversion.c */
  #define CFLAGS "compiler: $cc $cflags"
  #define PLATFORM "$platform"
EOF
printf OUT "  #define DATE \"%s\"\n", scalar gmtime();
printf OUT "#endif\n";
close(OUT);

# Strip off trailing ' '
foreach (keys %lib_obj) { $lib_obj{$_}=&clean_up_ws($lib_obj{$_}); }
$test=&clean_up_ws($test);
$e_exe=&clean_up_ws($e_exe);
$exheader=&clean_up_ws($exheader);
$header=&clean_up_ws($header);

# First we strip the exheaders from the headers list
foreach (split(/\s+/,$exheader)){ $h{$_}=1; }
foreach (split(/\s+/,$header))	{ $h.=$_." " unless $h{$_}; }
chop($h); $header=$h;

$defs.=&do_defs("HEADER",$header,"\$(INCL_D)","");
$rules.=&do_copy_rule("\$(INCL_D)",$header,"");

$defs.=&do_defs("EXHEADER",$exheader,"\$(INCO_D)","");
$rules.=&do_copy_rule("\$(INCO_D)",$exheader,"");

$defs.=&do_defs("T_OBJ","$test test${o}ssltestlib","\$(OBJ_D)",$obj);
$rules.=&do_compile_rule("\$(OBJ_D)","$test test${o}ssltestlib","\$(APP_CFLAGS)");

$defs.=&do_defs("E_OBJ",$e_exe,"\$(OBJ_D)",$obj);
$rules.=&do_compile_rule("\$(OBJ_D)",$e_exe,'-DMONOLITH $(APP_CFLAGS)');

# Special case rule for fips_premain_dso

if ($fips)
	{
	$rules.=&cc_compile_target("\$(OBJ_D)${o}\$(E_PREMAIN_DSO)$obj",
		"\$(FIPS_PREMAIN_SRC)",
		"-DFINGERPRINT_PREMAIN_DSO_LOAD \$(APP_CFLAGS)", "");
	$rules.=&do_link_rule("\$(PREMAIN_DSO_EXE)","\$(OBJ_D)${o}\$(E_PREMAIN_DSO)$obj \$(CRYPTOOBJ) \$(O_FIPSCANISTER)","","\$(EX_LIBS)", 1);
	}

sub fix_asm
	{
	my($asm, $dir) = @_;

	return '' if $asm eq '';

	$asm = " $asm";
	$asm =~ s/\s+/ $dir\//g;
	$asm =~ s/\.o//g;
	$asm =~ s/^ //;

	return $asm . ' ';
	}

if ($orig_platform eq 'copy') {
	$lib_obj{CRYPTO} .= fix_asm($mf_md5_asm, 'crypto/md5');
	$lib_obj{CRYPTO} .= fix_asm($mf_bn_asm, 'crypto/bn');
	# cpuid is included by the crypto dir
	#$lib_obj{CRYPTO} .= fix_asm($mf_cpuid_asm, 'crypto');
	# AES asm files DON'T end up included by the aes dir itself
	$lib_obj{CRYPTO} .= fix_asm($mf_aes_asm, 'crypto/aes');
	$lib_obj{CRYPTO} .= fix_asm($mf_sha_asm, 'crypto/sha');
	$lib_obj{CRYPTO} .= fix_asm($mf_engines_asm, 'engines');
	$lib_obj{CRYPTO} .= fix_asm($mf_rc4_asm, 'crypto/rc4');
	$lib_obj{CRYPTO} .= fix_asm($mf_modes_asm, 'crypto/modes');
	$lib_obj{CRYPTO} .= fix_asm($mf_ec_asm, 'crypto/ec');
}

foreach (values %lib_nam)
	{
	$lib_obj=$lib_obj{$_};
	local($slib)=$shlib;

	$defs.=&do_defs(${_}."OBJ",$lib_obj,"\$(OBJ_D)",$obj);
	$lib=($slib)?" \$(SHLIB_CFLAGS)".$shlib_ex_cflags{$_}:" \$(LIB_CFLAGS)";
	$rules.=&do_compile_rule("\$(OBJ_D)",$lib_obj{$_},$lib);
	}

# hack to add version info on MSVC
#Akamai if (($platform eq "VC-WIN32") || ($platform eq "VC-WIN64A")
#Akamai	|| ($platform eq "VC-WIN64I") || ($platform eq "VC-NT")) {
if (($platform eq "VC-WIN32") || ($platform eq "VC-WIN64A")
	|| ($platform eq "akamai-VC-WIN32") || ($platform eq "akamai-VC-WIN64A")
	|| ($platform eq "VC-WIN64I") || ($platform =~ /VC-NT/)) {
    $rules.= <<"EOF";
\$(OBJ_D)\\\$(CRYPTO).res: ms\\version32.rc
	\$(RSC) /fo"\$(OBJ_D)\\\$(CRYPTO).res" /d CRYPTO ms\\version32.rc

\$(OBJ_D)\\\$(SSL).res: ms\\version32.rc
	\$(RSC) /fo"\$(OBJ_D)\\\$(SSL).res" /d SSL ms\\version32.rc

EOF
}

$defs.=&do_defs("T_EXE",$test,"\$(TEST_D)",$exep);
foreach (split(/\s+/,$test))
	{
	$t=&bname($_);
	$tt="\$(OBJ_D)${o}$t${obj}";
	$tt.=" \$(OBJ_D)${o}ssltestlib${obj}" if $t eq "dtlstest";
	$rules.=&do_link_rule("\$(TEST_D)$o$t$exep",$tt,"\$(LIBS_DEP)","\$(L_LIBS) \$(EX_LIBS)");
	}

$defs.=&do_defs("E_SHLIB",$engines . $otherlibs,"\$(ENG_D)",$shlibp);

foreach (split(/\s+/,$engines))
	{
	$rules.=&do_compile_rule("\$(OBJ_D)","engines${o}e_$_",$lib);
	$rules.= &do_lib_rule("\$(OBJ_D)${o}e_${_}.obj","\$(ENG_D)$o$_$shlibp","",$shlib,"");
	}



$rules.= &do_lib_rule("\$(SSLOBJ)","\$(O_SSL)",$ssl,$shlib,"\$(SO_SSL)");

if ($fips)
	{
	if ($shlib)
		{
		$rules.= &do_lib_rule("\$(CRYPTOOBJ) \$(O_FIPSCANISTER)",
				"\$(O_CRYPTO)", "$crypto",
				$shlib, "\$(SO_CRYPTO)", "\$(BASEADDR)");
		}
	else
		{
		$rules.= &do_lib_rule("\$(CRYPTOOBJ)",
			"\$(O_CRYPTO)",$crypto,$shlib,"\$(SO_CRYPTO)", "");
		$rules.= &do_lib_rule("\$(CRYPTOOBJ) \$(O_FIPSCANISTER)",
			"\$(LIB_D)$o$crypto_compat",$crypto,$shlib,"\$(SO_CRYPTO)", "");
		}
	}
	else
	{
	$rules.= &do_lib_rule("\$(CRYPTOOBJ)","\$(O_CRYPTO)",$crypto,$shlib,
							"\$(SO_CRYPTO)");
	}

foreach (split(" ",$otherlibs))
	{
	my $uc = $_;
	$uc =~ tr /a-z/A-Z/;	
	$rules.= &do_lib_rule("\$(${uc}OBJ)","\$(ENG_D)$o$_$shlibp", "", $shlib, "");

	}

$rules.=&do_link_rule("\$(BIN_D)$o\$(E_EXE)$exep","\$(E_OBJ)","\$(LIBS_DEP)","\$(L_LIBS) \$(EX_LIBS)", ($fips && !$shlib) ? 2 : 0);

$rules .= get_tests('test/Makefile') if $orig_platform eq 'copy';

print $defs;

if ($platform eq "linux-elf") {
    print <<"EOF";
# Generate perlasm output files
%.cpp:
	(cd \$(\@D)/..; PERL=perl make -f Makefile asm/\$(\@F))
EOF
}
print "###################################################################\n";
print $rules;

###############################################
# strip off any trailing .[och] and append the relative directory
# also remembering to do nothing if we are in one of the dropped
# directories
sub var_add
	{
	local($dir,$val,$keepext)=@_;
	local(@a,$_,$ret);

	return("") if $no_engine && $dir =~ /\/engine/;
	return("") if $no_hw   && $dir =~ /\/hw/;
	return("") if $no_idea && $dir =~ /\/idea/;
	return("") if $no_aes  && $dir =~ /\/aes/;
	return("") if $no_camellia  && $dir =~ /\/camellia/;
	return("") if $no_seed && $dir =~ /\/seed/;
	return("") if $no_rc2  && $dir =~ /\/rc2/;
	return("") if $no_rc4  && $dir =~ /\/rc4/;
	return("") if $no_rc5  && $dir =~ /\/rc5/;
	return("") if $no_rsa  && $dir =~ /\/rsa/;
	return("") if $no_rsa  && $dir =~ /^rsaref/;
	return("") if $no_dsa  && $dir =~ /\/dsa/;
	return("") if $no_dh   && $dir =~ /\/dh/;
	return("") if $no_ec   && $dir =~ /\/ec/;
	return("") if $no_gost   && $dir =~ /\/ccgost/;
	return("") if $no_cms  && $dir =~ /\/cms/;
	return("") if $no_jpake  && $dir =~ /\/jpake/;
	return("") if $no_comp && $dir =~ /\/comp/;
	if ($no_des && $dir =~ /\/des/)
		{
		if ($val =~ /read_pwd/)
			{ return("$dir/read_pwd "); }
		else
			{ return(""); }
		}
	return("") if $no_mdc2 && $dir =~ /\/mdc2/;
	return("") if $no_sock && $dir =~ /\/proxy/;
	return("") if $no_bf   && $dir =~ /\/bf/;
	return("") if $no_cast && $dir =~ /\/cast/;
	return("") if $no_whirlpool && $dir =~ /\/whrlpool/;

	$val =~ s/^\s*(.*)\s*$/$1/;
	@a=split(/\s+/,$val);
	grep(s/\.[och]$//,@a) unless $keepext;

	@a=grep(!/^e_.*_3d$/,@a) if $no_des;
	@a=grep(!/^e_.*_d$/,@a) if $no_des;
	@a=grep(!/^e_.*_ae$/,@a) if $no_idea;
	@a=grep(!/^e_.*_i$/,@a) if $no_aes;
	@a=grep(!/^e_.*_r2$/,@a) if $no_rc2;
	@a=grep(!/^e_.*_r5$/,@a) if $no_rc5;
	@a=grep(!/^e_.*_bf$/,@a) if $no_bf;
	@a=grep(!/^e_.*_c$/,@a) if $no_cast;
	@a=grep(!/^e_rc4$/,@a) if $no_rc4;
	@a=grep(!/^e_camellia$/,@a) if $no_camellia;
	@a=grep(!/^e_seed$/,@a) if $no_seed;

	#@a=grep(!/(^s2_)|(^s23_)/,@a) if $no_ssl2;
	#@a=grep(!/(^s3_)|(^s23_)/,@a) if $no_ssl3;

	@a=grep(!/(_sock$)|(_acpt$)|(_conn$)|(^pxy_)/,@a) if $no_sock;

	@a=grep(!/(^md2)|(_md2$)/,@a) if $no_md2;
	@a=grep(!/(^md4)|(_md4$)/,@a) if $no_md4;
	@a=grep(!/(^md5)|(_md5$)/,@a) if $no_md5;
	@a=grep(!/(rmd)|(ripemd)/,@a) if $no_ripemd;

	@a=grep(!/(^d2i_r_)|(^i2d_r_)/,@a) if $no_rsa;
	@a=grep(!/(^p_open$)|(^p_seal$)/,@a) if $no_rsa;
	@a=grep(!/(^pem_seal$)/,@a) if $no_rsa;

	@a=grep(!/(m_dss$)|(m_dss1$)/,@a) if $no_dsa;
	@a=grep(!/(^d2i_s_)|(^i2d_s_)|(_dsap$)/,@a) if $no_dsa;

	@a=grep(!/^n_pkey$/,@a) if $no_rsa || $no_rc4;

	@a=grep(!/_dhp$/,@a) if $no_dh;

	@a=grep(!/(^sha[^1])|(_sha$)|(m_dss$)/,@a) if $no_sha;
	@a=grep(!/(^sha1)|(_sha1$)|(m_dss1$)/,@a) if $no_sha1;
	@a=grep(!/_mdc2$/,@a) if $no_mdc2;

	@a=grep(!/(srp)/,@a) if $no_srp;

	@a=grep(!/^engine$/,@a) if $no_engine;
	@a=grep(!/^hw$/,@a) if $no_hw;
	@a=grep(!/(^rsa$)|(^genrsa$)/,@a) if $no_rsa;
	@a=grep(!/(^dsa$)|(^gendsa$)|(^dsaparam$)/,@a) if $no_dsa;
	@a=grep(!/^gendsa$/,@a) if $no_sha1;
	@a=grep(!/(^dh$)|(^gendh$)/,@a) if $no_dh;

	@a=grep(!/(^dh)|(_sha1$)|(m_dss1$)/,@a) if $no_sha1;

	grep($_="$dir/$_",@a);
	@a=grep(!/(^|\/)s_/,@a) if $no_sock;
	@a=grep(!/(^|\/)bio_sock/,@a) if $no_sock;
	$ret=join(' ',@a)." ";
	return($ret);
	}

# change things so that each 'token' is only separated by one space
sub clean_up_ws
	{
	local($w)=@_;

	$w =~ s/^\s*(.*)\s*$/$1/;
	$w =~ s/\s+/ /g;
	return($w);
	}

sub do_defs
	{
	local($var,$files,$location,$postfix)=@_;
	local($_,$ret,$pf);
	local(*OUT,$tmp,$t);

	$files =~ s/\//$o/g if $o ne '/';
	$ret="$var="; 
	$n=1;
	$Vars{$var}.="";
	foreach (split(/ /,$files))
		{
		$orig=$_;
		$_=&bname($_) unless /^\$/;
		if ($n++ == 2)
			{
			$n=0;
			$ret.="\\\n\t";
			}
		if (($_ =~ /bss_file/) && ($postfix eq ".h"))
			{ $pf=".c"; }
		else	{ $pf=$postfix; }
		if ($_ =~ /BN_ASM/)	{ $t="$_ "; }
		elsif ($_ =~ /BNCO_ASM/){ $t="$_ "; }
		elsif ($_ =~ /AES_ASM/){ $t="$_ "; }
		elsif ($_ =~ /DES_ENC/)	{ $t="$_ "; }
		elsif ($_ =~ /BF_ENC/)	{ $t="$_ "; }
		elsif ($_ =~ /CAST_ENC/){ $t="$_ "; }
		elsif ($_ =~ /RC4_ENC/)	{ $t="$_ "; }
		elsif ($_ =~ /RC5_ENC/)	{ $t="$_ "; }
		elsif ($_ =~ /MD5_ASM/)	{ $t="$_ "; }
		elsif ($_ =~ /SHA1_ASM/){ $t="$_ "; }
		elsif ($_ =~ /RMD160_ASM/){ $t="$_ "; }
		elsif ($_ =~ /WHIRLPOOL_ASM/){ $t="$_ "; }
		elsif ($_ =~ /CPUID_ASM/){ $t="$_ "; }
		else	{ $t="$location${o}$_$pf "; }

		$Vars{$var}.="$t ";
		$ret.=$t;
		}
	# hack to add version info on MSVC
#Akamai	if ($shlib && (($platform eq "VC-WIN32") || ($platfrom eq "VC-WIN64I") || ($platform eq "VC-WIN64A") || ($platform eq "VC-NT")))
	if ($shlib && (($platform eq "VC-WIN32") || ($platfrom eq "VC-WIN64I") || ($platform eq "VC-WIN64A") || ($platform eq "akamai-VC-WIN32") || ($platform eq "akamai-VC-WIN64") || ($platform =~ /VC-NT/)))
		{
		if ($var eq "CRYPTOOBJ")
			{ $ret.="\$(OBJ_D)\\\$(CRYPTO).res "; }
		elsif ($var eq "SSLOBJ")
			{ $ret.="\$(OBJ_D)\\\$(SSL).res "; }
		}
	chomp($ret);
	$ret.="\n\n";
	return($ret);
	}

# return the name with the leading path removed
sub bname
	{
	local($ret)=@_;
	$ret =~ s/^.*[\\\/]([^\\\/]+)$/$1/;
	return($ret);
	}

# return the leading path
sub dname
	{
	my $ret=shift;
	$ret =~ s/(^.*)[\\\/][^\\\/]+$/$1/;
	return($ret);
	}

##############################################################
# do a rule for each file that says 'compile' to new direcory
# compile the files in '$files' into $to
sub do_compile_rule
	{
	local($to,$files,$ex)=@_;
	local($ret,$_,$n,$d,$s);

	$files =~ s/\//$o/g if $o ne '/';
	foreach (split(/\s+/,$files))
		{
		$n=&bname($_);
		$d=&dname($_);
		if (-f "${_}.c")
			{
			$ret.=&cc_compile_target("$to${o}$n$obj","${_}.c",$ex)
			}
		elsif (-f ($s="${d}${o}asm${o}${n}.pl") or
		       ($s=~s/sha256/sha512/ and -f $s) or
		       -f ($s="${d}${o}${n}.pl"))
			{
			$ret.=&perlasm_compile_target("$to${o}$n$obj",$s,$n);
			}
		elsif (-f ($s="${d}${o}asm${o}${n}.S") or
		       -f ($s="${d}${o}${n}.S"))
			{
			$ret.=&Sasm_compile_target("$to${o}$n$obj",$s,$n);
			}
		elsif (defined &special_compile_target and
		       ($s=special_compile_target($_)))
			{
			$ret.=$s;
			}
		else	{ die "no rule for $_"; }
		}
	return($ret);
	}

##############################################################
# do a rule for each file that says 'compile' to new direcory
sub perlasm_compile_target
	{
	my($target,$source,$bname)=@_;

	return platform_perlasm_compile_target($target, $source, $bname)
	    if defined &platform_perlasm_compile_target;

	my($ret);

	$bname =~ s/(.*)\.[^\.]$/$1/;
	$ret ="\$(TMP_D)$o$bname.asm: $source\n";
	$ret.="\t\$(PERL) $source $asmtype \$(CFLAG) >\$\@\n\n";
	$ret.="$target: \$(TMP_D)$o$bname.asm\n";
	$ret.="\t\$(ASM) $afile\$\@ \$(TMP_D)$o$bname.asm\n\n";
	return($ret);
	}

sub Sasm_compile_target
	{
	my($target,$source,$bname)=@_;
	my($ret);

	$bname =~ s/(.*)\.[^\.]$/$1/;
	$ret ="\$(TMP_D)$o$bname.asm: $source\n";
	$ret.="\t\$(CC) -E \$(CFLAG) $source >\$\@\n\n";
	$ret.="$target: \$(TMP_D)$o$bname.asm\n";
	$ret.="\t\$(ASM) $afile\$\@ \$(TMP_D)$o$bname.asm\n\n";
	return($ret);
	}

sub cc_compile_target
	{
	local($target,$source,$ex_flags, $srcd)=@_;
	local($ret);
	
	$ex_flags.=" -DMK1MF_BUILD -D$platform_cpp_symbol" if ($source =~ /cversion/);
	$target =~ s/\//$o/g if $o ne "/";
	$source =~ s/\//$o/g if $o ne "/";
	$srcd = "\$(SRC_D)$o" unless defined $srcd && $platform ne 'copy';
	$ret ="$target: $srcd$source\n\t";
	$ret.="\$(CC)";
	$ret.= " -MMD" if $orig_platform eq "copy";
	$ret.= " ${ofile}$target $ex_flags -c $srcd$source\n\n";
	$target =~ s/\.o$/.d/;
	$ret.=".sinclude \"$target\"\n\n" if $orig_platform eq "copy";
	return($ret);
	}

##############################################################
sub do_asm_rule
	{
	local($target,$src)=@_;
	local($ret,@s,@t,$i);

	$target =~ s/\//$o/g if $o ne "/";
	$src =~ s/\//$o/g if $o ne "/";

	@t=split(/\s+/,$target);
	@s=split(/\s+/,$src);


	for ($i=0; $i<=$#s; $i++)
		{
		my $objfile = $t[$i];
		my $srcfile = $s[$i];

		if ($perl_asm == 1)
			{
			my $plasm = $objfile;
			$plasm =~ s/${obj}/.pl/;
			$ret.="$srcfile: $plasm\n";
			$ret.="\t\$(PERL) $plasm $asmtype \$(CFLAG) >$srcfile\n\n";
			}

		$ret.="$objfile: $srcfile\n";
		$ret.="\t\$(ASM) $afile$objfile \$(SRC_D)$o$srcfile\n\n";
		}
	return($ret);
	}

sub do_shlib_rule
	{
	local($n,$def)=@_;
	local($ret,$nn);
	local($t);

	($nn=$n) =~ tr/a-z/A-Z/;
	$ret.="$n.dll: \$(${nn}OBJ)\n";
	if ($vc && $w32)
		{
		$ret.="\t\$(MKSHLIB) $efile$n.dll $def @<<\n  \$(${nn}OBJ_F)\n<<\n";
		}
	$ret.="\n";
	return($ret);
	}

# do a rule for each file that says 'copy' to new direcory on change
sub do_copy_rule
	{
	local($to,$files,$p)=@_;
	local($ret,$_,$n,$pp);
	
	$files =~ s/\//$o/g if $o ne '/';
	foreach (split(/\s+/,$files))
		{
		$n=&bname($_);
		if ($n =~ /bss_file/)
			{ $pp=".c"; }
		else	{ $pp=$p; }
		$ret.="$to${o}$n$pp: \$(SRC_D)$o$_$pp\n\t\$(PERL) \$(SRC_D)${o}util${o}copy-if-different.pl \"\$(SRC_D)$o$_$pp\" \"$to${o}$n$pp\"\n\n";
		}
	return($ret);
	}

# Options picked up from the OPTIONS line in the top level Makefile
# generated by Configure.

sub read_options
	{
	# Many options are handled in a similar way. In particular
	# no-xxx sets zero or more scalars to 1.
	# Process these using the %valid_options hash containing the option
	# name and reference to the scalars to set. In some cases the option
	# needs no special handling and can be ignored: this is done by
	# setting the value to 0.

	my %valid_options = (
		"no-rc2" => \$no_rc2,
		"no-rc4" => \$no_rc4,
		"no-rc5" => \$no_rc5,
		"no-idea" => \$no_idea,
		"no-aes" => \$no_aes,
		"no-camellia" => \$no_camellia,
		"no-seed" => \$no_seed,
		"no-des" => \$no_des,
		"no-bf" => \$no_bf,
		"no-cast" => \$no_cast,
		"no-md2" => \$no_md2,
		"no-md4" => \$no_md4,
		"no-md5" => \$no_md5,
		"no-sha" => \$no_sha,
		"no-sha1" => \$no_sha1,
		"no-ripemd" => \$no_ripemd,
		"no-mdc2" => \$no_mdc2,
		"no-whirlpool" => \$no_whirlpool,
		"no-patents" => 
			[\$no_rc2, \$no_rc4, \$no_rc5, \$no_idea, \$no_rsa],
		"no-rsa" => \$no_rsa,
		"no-dsa" => \$no_dsa,
		"no-dh" => \$no_dh,
		"no-hmac" => \$no_hmac,
		"no-asm" => \$no_asm,
		"nasm" => \$nasm,
		"nw-nasm" => \$nw_nasm,
		"nw-mwasm" => \$nw_mwasm,
		"gaswin" => \$gaswin,
		"no-ssl2" => \$no_ssl2,
		"no-ssl2-method" => 0,
		"no-ssl3" => \$no_ssl3,
		"no-tls1" => \$no_tls1,
		"no-dtls1" => \$no_dtls1,
		"no-ssl3-method" => 0,
		"no-tlsext" => \$no_tlsext,
		"no-tls1" => \$no_tls1,
		"no-dtls1" => 0,
		"no-srp" => \$no_srp,
		"no-cms" => \$no_cms,
		"no-jpake" => \$no_jpake,
		"no-ec2m" => \$no_ec2m,
		"no-ec_nistp_64_gcc_128" => 0,
		"no-weak-ssl-ciphers" => \$no_weak_ssl,
		"no-err" => \$no_err,
		"no-sock" => \$no_sock,
		"no-krb5" => \$no_krb5,
		"no-ec" => \$no_ec,
		"no-ecdsa" => \$no_ecdsa,
		"no-ecdh" => \$no_ecdh,
		"no-gost" => \$no_gost,
		"no-engine" => \$no_engine,
		"no-hw" => \$no_hw,
	        "no-buf-freelists" => \$no_buf_freelists,
	        "no-heartbeats" => \$no_heartbeats,
	        "no-akamai-async-rsalg" => \$no_akamai_async_rsalg, #Akamai
	        "no-akamai-ghost-high" => \$no_akamai_ghost_high, #Akamai
	        "no-akamai-client-cache" => \$no_akamai_client_cache, #Akamai
	        "no-psk" => \$no_psk,
		"no-rsax" => 0,
		"just-ssl" =>
			[\$no_rc2, \$no_idea, \$no_des, \$no_bf, \$no_cast,
			  \$no_md2, \$no_sha, \$no_mdc2, \$no_dsa, \$no_dh,
			  \$no_ssl2, \$no_err, \$no_ripemd, \$no_rc5,
			  \$no_aes, \$no_camellia, \$no_seed, \$no_srp],
		"rsaref" => 0,
		"gcc" => \$gcc,
		"debug" => \$debug,
		"profile" => \$profile,
		"shlib" => \$shlib,
		"dll" => \$shlib,
	        "akamaidebug" => \$debug, # Akamai
	        "dll_lib" => \$dll_lib,   # Akamai
		"shared" => 0,
		"no-sctp" => 0,
		"no-srtp" => 0,
		"no-gmp" => 0,
		"no-rfc3779" => 0,
		"no-montasm" => 0,
		"no-shared" => 0,
		"no-store" => 0,
		"no-zlib" => 0,
		"no-zlib-dynamic" => 0,
		"no-ssl-trace" => 0,
		"no-unit-test" => 0,
		"no-libunbound" => 0,
		"no-multiblock" => 0,
		"no-comp" => \$no_comp,
		"fips" => \$fips
		);

	if (exists $valid_options{$_})
		{
		my $r = $valid_options{$_};
		if ( ref $r eq "SCALAR")
			{ $$r = 1;}
		elsif ( ref $r eq "ARRAY")
			{
			my $r2;
			foreach $r2 (@$r)
				{
				$$r2 = 1;
				}
			}
		}
	elsif (/^enable-zlib$/) { $zlib_opt = 1 if $zlib_opt == 0 }
	elsif (/^enable-zlib-dynamic$/)
		{
		$zlib_opt = 2;
		}
	elsif (/^no-static-engine/)
		{
		$no_static_engine = 1;
		}
	elsif (/^enable-static-engine/)
		{
		$no_static_engine = 0;
		}
	elsif (/^no-dynamic-engine/)
		{
		$no_static_engine = 0;
		}
	elsif (/^enable-dynamic-engine/)
		{
		$no_static_engine = 1;
		}
	# There are also enable-xxx options which correspond to
	# the no-xxx. Since the scalars are enabled by default
	# these can be ignored.
	elsif (/^enable-/)
		{
		my $t = $_;
		$t =~ s/^enable/no/;
		if (exists $valid_options{$t})
			{return 1;}
		return 0;
		}
	# experimental-xxx is mostly like enable-xxx, but opensslconf.v
	# will still set OPENSSL_NO_xxx unless we set OPENSSL_EXPERIMENTAL_xxx.
	# (No need to fail if we don't know the algorithm -- this is for adventurous users only.)
	elsif (/^experimental-/)
		{
		my $algo, $ALGO;
		($algo = $_) =~ s/^experimental-//;
		($ALGO = $algo) =~ tr/[a-z]/[A-Z]/;

		$xcflags="-DOPENSSL_EXPERIMENTAL_$ALGO $xcflags";
		
		}
	elsif (/^--with-krb5-flavor=(.*)$/)
		{
		my $krb5_flavor = $1;
		if ($krb5_flavor =~ /^force-[Hh]eimdal$/)
			{
			$xcflags="-DKRB5_HEIMDAL $xcflags";
			}
		elsif ($krb5_flavor =~ /^MIT/i)
			{
			$xcflags="-DKRB5_MIT $xcflags";
		 	if ($krb5_flavor =~ /^MIT[._-]*1[._-]*[01]/i)
				{
				$xcflags="-DKRB5_MIT_OLD11 $xcflags"
				}
			}
		}
	elsif (/^([^=]*)=(.*)$/){ $VARS{$1}=$2; }
	elsif (/^-[lL].*$/)	{ $l_flags.="$_ "; }
	elsif ((!/^-help/) && (!/^-h/) && (!/^-\?/) && /^-.*$/)
		{ $c_flags.="$_ "; }
	else { return(0); }
	return(1);
	}
