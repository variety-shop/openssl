perl util\mkfiles.pl >MINFO

perl util\mk1mf.pl %1 no-asm VC-NT-%2 >ms\nt.mak
perl util\mk1mf.pl %1 dll_lib no-asm VC-NT-%2 >ms\ntdll_lib.mak
