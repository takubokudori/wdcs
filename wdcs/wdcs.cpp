/*
Copyright 2022 takubokudori https://github.com/takubokudori/wdcs
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#include <Windows.h>
#include <WDBGEXTS.H>
#include "util.h"
#include <TlHelp32.h>
#include <algorithm>
#include <set>
#include <string>
#define max(a,b)            (((a) > (b)) ? (a) : (b))

EXT_API_VERSION ApiVersion = {
	0,    // MajorVersion
	0,    // MinorVersion
	EXT_API_VERSION_NUMBER64,    // Revision
	0    // Reserved
};

WINDBG_EXTENSION_APIS ExtensionApis;

LPEXT_API_VERSION ExtensionApiVersion() {
	return &ApiVersion;
}

VOID WinDbgExtensionDllInit(
	PWINDBG_EXTENSION_APIS lpExtensionApis,
	USHORT MajorVersion,
	USHORT MinorVersion
) {
	UNREFERENCED_PARAMETER(MajorVersion);
	UNREFERENCED_PARAMETER(MinorVersion);
	ExtensionApis = *lpExtensionApis;
}

DECLARE_API64(help) {
	UNREFERENCED_PARAMETER(hCurrentProcess);
	UNREFERENCED_PARAMETER(hCurrentThread);
	UNREFERENCED_PARAMETER(dwCurrentPc);
	UNREFERENCED_PARAMETER(dwProcessor);
	UNREFERENCED_PARAMETER(args);
	dprintf(\
		"wdcs: A WinDbg extension to check the security features of the loaded modules with winchecksec\n" \
		"Version 1.0.0\n" \
		"\n" \
		"USAGE:\n" \
		"\t !wdcs.checksec <module name or full path> ... [OPTIONS]   Print the security features of the loaded modules\n" \
		"\t !wdcs.path <path>                                        Set the path of winchecksec\n" \
		"\t !wdcs.help                                               Show Help\n" \
		"\n" \
		"OPTIONS:\n" \
		"\t-f                  Show the loaded module full paths\n" \
		"\t-y                  Show only Present and Unknown features\n" \
		"\t-n                  Show only Not present and Unknown features\n" \
		"\t-m <feature> ...    Features to be printed\n" \
		"\t\t Dynamic Base    : d db dynamicbase\n" \
		"\t\t ASLR            : a as aslr\n" \
		"\t\t High Entropy VA : h heva highentropyva\n" \
		"\t\t Force Integrity : f fi forceintegrity\n" \
		"\t\t Isolation       : i is isolation\n" \
		"\t\t NX              : n nx xd xn\n" \
		"\t\t SEH             : s se seh\n" \
		"\t\t CFG             : c cf cfg\n" \
		"\t\t RFG             : r rf rfg\n" \
		"\t\t SafeSEH         : ss sseh safeseh\n" \
		"\t\t GS              : g gs canary\n" \
		"\t\t Authenticode    : au auth authenticode\n" \
		"\t\t DotNET          : dn dotnet .net\n" \
		"\n" \
		"EXAMPLE:\n" \
		"\t !wdcs.checksec\n" \
		"\t !wdcs.path C:\\path\\to\\the\\winchecksec.exe\n" \
		"\t !wdcs.checksec ntdll.dll notepad.exe -m aslr gs\n");
}

DECLARE_API64(path)
{
	UNREFERENCED_PARAMETER(hCurrentProcess);
	UNREFERENCED_PARAMETER(hCurrentThread);
	UNREFERENCED_PARAMETER(dwCurrentPc);
	UNREFERENCED_PARAMETER(dwProcessor);
	auto p = MultiByteToWideCharWrap(args, static_cast<int>(strlen(args)));
	if (!p)
	{
		winCheckSecPath = std::nullopt;
		dprintf("Set default winchecksec path\n");
		return;
	}
	auto p2 = std::wstring(p);
	free(p);
	if (p2.empty())
	{
		winCheckSecPath = std::nullopt;
		dprintf("Set default winchecksec path\n");
		return;
	}
	winCheckSecPath = p2;
	dprintf("Set winchecksec path: %ls\n", winCheckSecPath.value().c_str());
}

class PrintOptions
{
public:
	bool DynamicBase;
	bool ASLR;
	bool HighEntropyVA;
	bool ForceIntegrity;
	bool Isolation;
	bool NX;
	bool SEH;
	bool CFG;
	bool RFG;
	bool SafeSEH;
	bool GS;
	bool Authenticode;
	bool DotNET;

	PrintOptions()
	{
		SetAll();
	}
	void SetAll()
	{
		DynamicBase = ASLR = HighEntropyVA = \
			ForceIntegrity = Isolation = NX = \
			SEH = CFG = RFG = SafeSEH = \
			GS = Authenticode = DotNET = true;
	}
	void Clear()
	{
		DynamicBase = ASLR = HighEntropyVA = \
			ForceIntegrity = Isolation = NX = \
			SEH = CFG = RFG = SafeSEH = \
			GS = Authenticode = DotNET = false;
	}
};

enum CurOpt
{
	Path,
	Mitigation,
};

void ParseArgs(PCSTR args, PrintOptions& po, std::set<std::wstring>& paths, bool& useFullPath, bool& showYes, bool& showNo)
{
	std::string args1(args);
	auto opts = Split(args1, ' ');
	int now = CurOpt::Path;
	useFullPath = false;
	showYes = true;
	showNo = true;
	for (auto& arg : opts)
	{
		if (arg.empty()) continue;
		if (arg == "-m")
		{
			// mitigation name
			po.Clear();
			now = CurOpt::Mitigation;
		}
		else if (arg == "-f")
		{
			useFullPath = true;
		}
		else if (arg == "-y")
		{
			if (!showYes)
			{
				dprintf("Warning: -y and -n are mutually exclusive\n");
				continue;
			}
			showYes = true;
			showNo = false;
		}
		else if (arg == "-n")
		{
			if (!showNo)
			{
				dprintf("Warning: -y and -n are mutually exclusive\n");
				continue;
			}
			showYes = false;
			showNo = true;
		}
		else if (arg == "-p")
		{
			// path
			now = CurOpt::Path;
		}
		else
		{
			switch (now)
			{
			case CurOpt::Mitigation:
				arg = ToLowerA(arg);
				if (arg == "d" || arg == "db" || arg == "dynamicbase")
				{
					po.DynamicBase = true;
				}
				else if (arg == "a" || arg == "as" || arg == "aslr")
				{
					po.ASLR = true;
				}
				else if (arg == "h" || arg == "heva" || arg == "highentropyva")
				{
					po.HighEntropyVA = true;
				}
				else if (arg == "f" || arg == "fi" || arg == "forceintegrity")
				{
					po.ForceIntegrity = true;
				}
				else if (arg == "i" || arg == "is" || arg == "isolation")
				{
					po.Isolation = true;
				}
				else if (arg == "n" || arg == "nx" || arg == "xd" || arg == "xn")
				{
					po.NX = true;
				}
				else if (arg == "s" || arg == "se" || arg == "seh")
				{
					po.SEH = true;
				}
				else if (arg == "c" || arg == "cf" || arg == "cfg")
				{
					po.CFG = true;
				}
				else if (arg == "r" || arg == "rf" || arg == "rfg")
				{
					po.RFG = true;
				}
				else if (arg == "ss" || arg == "sseh" || arg == "safeseh")
				{
					po.SafeSEH = true;
				}
				else if (arg == "g" || arg == "gs" || arg == "canary")
				{
					po.GS = true;
				}
				else if (arg == "au" || arg == "auth" || arg == "authenticode")
				{
					po.Authenticode = true;
				}
				else if (arg == "dn" || arg == "dotnet" || arg == ".net")
				{
					po.DotNET = true;
				}
				else
				{
					dprintf("Unknown mitigation name: %s\n", arg.c_str());
				}
				break;
			case CurOpt::Path:
				const auto wa = MultiByteToWideCharWrap(arg.c_str(), static_cast<int>(arg.length()));
				if (!wa)
				{
					dprintf("Failed to convert string to wstring: %s", arg.c_str());
					continue;
				}
				auto wa2 = ToLowerW(std::wstring(wa));
				paths.insert(wa2);
				free(wa);
				break;
			}
		}
	}
}

void PrintInfos(const std::vector<ModInfo>& modInfos, const PrintOptions& po, const size_t maxLen, const bool useFullPath, bool showYes, bool showNo)
{
#if defined(_M_X64) // x64
	dprintf("start            end              module name");
#else
	dprintf("start    end      module name");
#endif
	if (maxLen > 12)
	{
		for (size_t i = 0; i < maxLen - 12 + 1; i++)
		{
			dprintf(" ");
		}
	}

	if (po.DynamicBase)
	{
		dprintf(" " STR_DB);
	}
	if (po.ASLR)
	{
		dprintf(" " STR_ASLR);
	}
	if (po.HighEntropyVA)
	{
		dprintf(" " STR_HEVA);
	}
	if (po.ForceIntegrity)
	{
		dprintf(" " STR_FI);
	}
	if (po.Isolation)
	{
		dprintf(" " STR_ISO);
	}
	if (po.NX)
	{
		dprintf(" " STR_NX);
	}
	if (po.SEH)
	{
		dprintf(" " STR_SEH);
	}
	if (po.CFG)
	{
		dprintf(" " STR_CFG);
	}
	if (po.RFG)
	{
		dprintf(" " STR_RFG);
	}
	if (po.SafeSEH)
	{
		dprintf(" " STR_SSEH);
	}
	if (po.GS)
	{
		dprintf(" " STR_GS);
	}
	if (po.Authenticode)
	{
		dprintf(" " STR_AUTH);
	}
	if (po.DotNET)
	{
		dprintf(" " STR_DN);
	}
	dprintf("\n");
	for (const auto& d : modInfos)
	{
#if defined(_M_X64) // x64
		dprintf("%p ", d.baseAddr);
		dprintf("%p ", d.baseAddr + d.baseSize);
#else
		dprintf("%p ", d.baseAddr);
		dprintf("%p ", d.baseAddr + d.baseSize);
#endif
		if (useFullPath)
		{
			dprintf("%ls ", d.fullPath.c_str());
			for (size_t i = 0; i < maxLen - d.fullPath.length(); i++) dprintf(" ");
		}
		else
		{
			dprintf("%ls ", d.modName.c_str());
			for (size_t i = 0; i < maxLen - d.modName.length(); i++) dprintf(" ");
		}

		if (po.DynamicBase)
		{
			dprintf("     %s      ", MPToStr(d.mi.DynamicBase, showYes, showNo));
		}
		if (po.ASLR)
		{
			dprintf(" %s   ", MPToStr(d.mi.ASLR, showYes, showNo));
		}
		if (po.HighEntropyVA)
		{
			dprintf("      %s       ", MPToStr(d.mi.HighEntropyVA, showYes, showNo));
		}
		if (po.ForceIntegrity)
		{
			dprintf("       %s       ", MPToStr(d.mi.ForceIntegrity, showYes, showNo));
		}
		if (po.Isolation)
		{
			dprintf("    %s     ", MPToStr(d.mi.Isolation, showYes, showNo));
		}
		if (po.NX)
		{
			dprintf("%s  ", MPToStr(d.mi.NX, showYes, showNo));
		}
		if (po.SEH)
		{
			dprintf(" %s  ", MPToStr(d.mi.SEH, showYes, showNo));
		}
		if (po.CFG)
		{
			dprintf(" %s  ", MPToStr(d.mi.CFG, showYes, showNo));
		}
		if (po.RFG)
		{
			dprintf(" %s  ", MPToStr(d.mi.RFG, showYes, showNo));
		}
		if (po.SafeSEH)
		{
			dprintf("   %s    ", MPToStr(d.mi.SafeSEH, showYes, showNo));
		}
		if (po.GS)
		{
			dprintf("%s  ", MPToStr(d.mi.GS, showYes, showNo));
		}
		if (po.Authenticode)
		{
			dprintf("     %s       ", MPToStr(d.mi.Authenticode, showYes, showNo));
		}
		if (po.DotNET)
		{
			dprintf("  %s    ", MPToStr(d.mi.DotNET, showYes, showNo));
		}
		dprintf("\n");
	}

}

bool GetModuleInfo(const std::set<std::wstring>& paths, const DWORD pid, std::vector<ModInfo>& modInfos, size_t& maxFullPathLen, size_t& maxModNameLen)
{
	const HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	maxFullPathLen = 0;
	maxModNameLen = 0;
	if (!hSnapShot)
	{
		dprintf("CreateToolhelp32Snapshot failed\n");
		return false;
	}
	MODULEENTRY32W entry;
	entry.dwSize = sizeof(entry);
	auto f = Module32FirstW(hSnapShot, &entry);
	while (f)
	{
		ModInfo d = {
			std::wstring(entry.szExePath),
			std::wstring(entry.szModule),
			entry.modBaseAddr,
			entry.modBaseSize
		};
		auto modName = ToLowerW(d.modName);
		auto fullPath = ToLowerW(d.fullPath);
		if (paths.empty() || paths.contains(modName) || paths.contains(fullPath)) {
			DoWinCheckSec(entry.szExePath, d.mi);
			maxFullPathLen = max(maxFullPathLen, d.fullPath.length());
			maxModNameLen = max(maxModNameLen, d.modName.length());
			modInfos.push_back(d);
		}
		f = Module32Next(hSnapShot, &entry);
	}
	CloseHandle(hSnapShot);
	return true;
}

DECLARE_API64(checksec) {
	UNREFERENCED_PARAMETER(hCurrentThread);
	UNREFERENCED_PARAMETER(dwCurrentPc);
	UNREFERENCED_PARAMETER(dwProcessor);
	PrintOptions po;
	std::set<std::wstring> paths;
	bool useFullPath, showYes, showNo;

	ParseArgs(args, po, paths, useFullPath, showYes, showNo);

	const auto pid = GetProcessId(hCurrentProcess);
	std::vector<ModInfo> modInfos;
	size_t maxFullPathLen, maxModNameLen;

	GetModuleInfo(paths, pid, modInfos, maxFullPathLen, maxModNameLen);
	std::ranges::sort(modInfos, [](const ModInfo& a, const ModInfo& b)
		{
			return a.baseAddr < b.baseAddr;
		});

	size_t maxLen;
	if (useFullPath)
	{
		maxLen = maxFullPathLen;
	}
	else
	{
		maxLen = maxModNameLen;
	}
	PrintInfos(modInfos, po, maxLen, useFullPath, showYes, showNo);
}

