perl util\mkfiles.pl >MINFO

REM Put all the arguments, except the last one, into %args%
SET args=
SET last=
:again
SET args=%args% %last%
SET last=%1
SHIFT
IF NOT [%1]==[] GOTO again

perl util\mk1mf.pl %args% no-asm VC-NT-%last% >ms\nt.mak
perl util\mk1mf.pl %args% dll_lib no-asm VC-NT-%last% >ms\ntdll_lib.mak
