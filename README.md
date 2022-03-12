# WinDbgCheckSec

A WinDbg extension to check the security features of the loaded modules with [winchecksec](https://github.com/trailofbits/winchecksec).

# Usage

1. Install [winchecksec](https://github.com/trailofbits/winchecksec).

The default wdcs.path is `winchecksec`.

```
0:000> !wdcs.help
wdcs: A WinDbg extension to check the security features of the loaded modules with winchecksec
Version 1.0.0

USAGE:
	 !wdcs.checksec <module name or full path> ... [OPTIONS]   Print the security features of the loaded modules
	 !wdcs.path <path>                                        Set the path of winchecksec
	 !wdcs.help                                               Show Help

OPTIONS:
	-f                  Show the loaded module full paths
	-y                  Show only Present and Unknown features
	-n                  Show only Not present and Unknown features
	-m <feature> ...    Features to be printed
		 Dynamic Base    : d db dynamicbase
		 ASLR            : a as aslr
		 High Entropy VA : h heva highentropyva
		 Force Integrity : f fi forceintegrity
		 Isolation       : i is isolation
		 NX              : n nx xd xn
		 SEH             : s se seh
		 CFG             : c cf cfg
		 RFG             : r rf rfg
		 SafeSEH         : ss sseh safeseh
		 GS              : g gs canary
		 Authenticode    : a auth authenticode
		 DotNET          : dn dotnet .net

EXAMPLE:
	 !wdcs.checksec
	 !wdcs.path C:\path\to\the\winchecksec.exe
	 !wdcs.checksec ntdll.dll notepad.exe -m aslr gs
```

# Example

```
0:000> .load C:\path\to\the\x64\wdcs.dll
0:000> !checksec
start            end              module name    DynamicBase ASLR HighEntropyVA ForceIntegrity Isolation NX SEH CFG RFG SafeSEH GS Authenticode DotNET
00007ff6c3090000 00007ff6c30c8000 notepad.exe         Y       Y         Y              N           Y     Y   Y   Y   N     N    Y       N         N    
00007ffefdcc0000 00007ffefdf5a000 COMCTL32.dll        Y       Y         Y              N           Y     Y   Y   Y   N     N    Y       Y         N    
00007fff194f0000 00007fff197b8000 KERNELBASE.dll      Y       Y         Y              N           Y     Y   Y   Y   N     N    Y       Y         N    
00007fff197c0000 00007fff1985d000 msvcp_win.dll       Y       Y         Y              N           Y     Y   Y   Y   N     N    Y       Y         N    
00007fff199a0000 00007fff19aab000 gdi32full.dll       Y       Y         Y              N           Y     Y   Y   Y   N     N    Y       Y         N    
00007fff19c60000 00007fff19c82000 win32u.dll          Y       Y         Y              N           Y     Y   Y   Y   N     N    Y       Y         N    
00007fff19c90000 00007fff19d90000 ucrtbase.dll        Y       Y         Y              N           Y     Y   Y   Y   N     N    Y       Y         N    
00007fff19fd0000 00007fff1a06e000 msvcrt.dll          Y       Y         Y              N           Y     Y   Y   Y   N     N    Y       Y         N    
00007fff1ad90000 00007fff1b0e4000 combase.dll         Y       Y         Y              N           Y     Y   Y   Y   N     N    Y       Y         N    
00007fff1b220000 00007fff1b3c0000 USER32.dll          Y       Y         Y              N           Y     Y   Y   Y   N     N    Y       Y         N    
00007fff1b680000 00007fff1b6ab000 GDI32.dll           Y       Y         Y              N           Y     Y   Y   Y   N     N    Y       Y         N    
00007fff1b6c0000 00007fff1b7e5000 RPCRT4.dll          Y       Y         Y              N           Y     Y   Y   Y   N     N    Y       Y         N    
00007fff1b820000 00007fff1b8cd000 shcore.dll          Y       Y         Y              N           Y     Y   Y   Y   N     N    Y       Y         N    
00007fff1bb30000 00007fff1bbee000 KERNEL32.DLL        Y       Y         Y              N           Y     Y   Y   Y   N     N    Y       Y         N    
00007fff1bdd0000 00007fff1bfc5000 ntdll.dll           Y       Y         Y              N           Y     Y   Y   Y   N     N    Y       Y         N    
0:000> !checksec -f
start            end              module name                                                                                                                  DynamicBase ASLR HighEntropyVA ForceIntegrity Isolation NX SEH CFG RFG SafeSEH GS Authenticode DotNET
00007ff6c3090000 00007ff6c30c8000 C:\Windows\notepad.exe                                                                                                            Y       Y         Y              N           Y     Y   Y   Y   N     N    Y       N         N    
00007ffefdcc0000 00007ffefdf5a000 C:\WINDOWS\WinSxS\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.19041.1110_none_60b5254171f9507e\COMCTL32.dll      Y       Y         Y              N           Y     Y   Y   Y   N     N    Y       Y         N    
00007fff194f0000 00007fff197b8000 C:\WINDOWS\System32\KERNELBASE.dll                                                                                                Y       Y         Y              N           Y     Y   Y   Y   N     N    Y       Y         N    
00007fff197c0000 00007fff1985d000 C:\WINDOWS\System32\msvcp_win.dll                                                                                                 Y       Y         Y              N           Y     Y   Y   Y   N     N    Y       Y         N    
00007fff199a0000 00007fff19aab000 C:\WINDOWS\System32\gdi32full.dll                                                                                                 Y       Y         Y              N           Y     Y   Y   Y   N     N    Y       Y         N    
00007fff19c60000 00007fff19c82000 C:\WINDOWS\System32\win32u.dll                                                                                                    Y       Y         Y              N           Y     Y   Y   Y   N     N    Y       Y         N    
00007fff19c90000 00007fff19d90000 C:\WINDOWS\System32\ucrtbase.dll                                                                                                  Y       Y         Y              N           Y     Y   Y   Y   N     N    Y       Y         N    
00007fff19fd0000 00007fff1a06e000 C:\WINDOWS\System32\msvcrt.dll                                                                                                    Y       Y         Y              N           Y     Y   Y   Y   N     N    Y       Y         N    
00007fff1ad90000 00007fff1b0e4000 C:\WINDOWS\System32\combase.dll                                                                                                   Y       Y         Y              N           Y     Y   Y   Y   N     N    Y       Y         N    
00007fff1b220000 00007fff1b3c0000 C:\WINDOWS\System32\USER32.dll                                                                                                    Y       Y         Y              N           Y     Y   Y   Y   N     N    Y       Y         N    
00007fff1b680000 00007fff1b6ab000 C:\WINDOWS\System32\GDI32.dll                                                                                                     Y       Y         Y              N           Y     Y   Y   Y   N     N    Y       Y         N    
00007fff1b6c0000 00007fff1b7e5000 C:\WINDOWS\System32\RPCRT4.dll                                                                                                    Y       Y         Y              N           Y     Y   Y   Y   N     N    Y       Y         N    
00007fff1b820000 00007fff1b8cd000 C:\WINDOWS\System32\shcore.dll                                                                                                    Y       Y         Y              N           Y     Y   Y   Y   N     N    Y       Y         N    
00007fff1bb30000 00007fff1bbee000 C:\WINDOWS\System32\KERNEL32.DLL                                                                                                  Y       Y         Y              N           Y     Y   Y   Y   N     N    Y       Y         N    
00007fff1bdd0000 00007fff1bfc5000 C:\WINDOWS\SYSTEM32\ntdll.dll                                                                                                     Y       Y         Y              N           Y     Y   Y   Y   N     N    Y       Y         N    
0:000> !checksec -n
start            end              module name    DynamicBase ASLR HighEntropyVA ForceIntegrity Isolation NX SEH CFG RFG SafeSEH GS Authenticode DotNET
00007ff6c3090000 00007ff6c30c8000 notepad.exe                                          N                             N     N            N         N    
00007ffefdcc0000 00007ffefdf5a000 COMCTL32.dll                                         N                             N     N                      N    
00007fff194f0000 00007fff197b8000 KERNELBASE.dll                                       N                             N     N                      N    
00007fff197c0000 00007fff1985d000 msvcp_win.dll                                        N                             N     N                      N    
00007fff199a0000 00007fff19aab000 gdi32full.dll                                        N                             N     N                      N    
00007fff19c60000 00007fff19c82000 win32u.dll                                           N                             N     N                      N    
00007fff19c90000 00007fff19d90000 ucrtbase.dll                                         N                             N     N                      N    
00007fff19fd0000 00007fff1a06e000 msvcrt.dll                                           N                             N     N                      N    
00007fff1ad90000 00007fff1b0e4000 combase.dll                                          N                             N     N                      N    
00007fff1b220000 00007fff1b3c0000 USER32.dll                                           N                             N     N                      N    
00007fff1b680000 00007fff1b6ab000 GDI32.dll                                            N                             N     N                      N    
00007fff1b6c0000 00007fff1b7e5000 RPCRT4.dll                                           N                             N     N                      N    
00007fff1b820000 00007fff1b8cd000 shcore.dll                                           N                             N     N                      N    
00007fff1bb30000 00007fff1bbee000 KERNEL32.DLL                                         N                             N     N                      N    
00007fff1bdd0000 00007fff1bfc5000 ntdll.dll                                            N                             N     N                      N    
0:000> !checksec ntdll.dll notepad.exe -m aslr auth
start            end              module name ASLR Authenticode
00007ff6c3090000 00007ff6c30c8000 notepad.exe  Y        N       
00007fff1bdd0000 00007fff1bfc5000 ntdll.dll    Y        Y       
```

