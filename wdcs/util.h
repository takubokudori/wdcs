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
#pragma once
#define KDEXT_64BIT 
#include <Psapi.h>
#include <Windows.h>
#include <WDBGEXTS.H>
#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#define STR_DB "DynamicBase"
#define STR_ASLR "ASLR"
#define STR_HEVA "HighEntropyVA"
#define STR_FI "ForceIntegrity"
#define STR_ISO "Isolation"
#define STR_NX "NX"
#define STR_SEH "SEH"
#define STR_CFG "CFG"
#define STR_RFG "RFG"
#define STR_SSEH "SafeSEH"
#define STR_GS "GS"
#define STR_AUTH "Authenticode"
#define STR_DN "DotNET"

std::optional<std::wstring> winCheckSecPath;

enum class MitigationPresence {
	Unknown,
	Present,
	NotPresent,
	NotApplicable,
	NotImplemented,
};

typedef struct
{
	MitigationPresence DynamicBase;
	MitigationPresence ASLR;
	MitigationPresence HighEntropyVA;
	MitigationPresence ForceIntegrity;
	MitigationPresence Isolation;
	MitigationPresence NX;
	MitigationPresence SEH;
	MitigationPresence CFG;
	MitigationPresence RFG;
	MitigationPresence SafeSEH;
	MitigationPresence GS;
	MitigationPresence Authenticode;
	MitigationPresence DotNET;
} MitigationInfo;

typedef struct
{
	std::wstring fullPath;
	std::wstring modName;
	byte* baseAddr;
	DWORD baseSize;
	MitigationInfo mi;
}ModInfo;

std::string Trim(std::string& str)
{
	size_t i, i2;
	for (i = 0; i < str.size() && (str[i] == '\r' || str[i] == ' ' || str[i] == '\n'); i++);
	for (i2 = str.size() - 1; i2 >= 0 && (str[i2] == '\r' || str[i2] == ' ' || str[i2] == '\n'); i2--);
	auto sv = str.substr(i, i2 - i + 1);
	return sv;
}

std::vector<std::string> Split(std::string& s, const char sep)
{
	std::vector<std::string> v;
	std::string::size_type p0 = 0;
	while (true)
	{
		const auto p1 = s.find(sep, p0);
		if (p1 == std::string::npos)
		{
			v.push_back(s.substr(p0));
			return v;
		}
		v.push_back(s.substr(p0, p1 - p0));
		p0 = p1 + 1;
	}
}

MitigationPresence ToMP(const std::string& status)
{
	if (status == "\"Present\"")
	{
		return MitigationPresence::Present;
	}if (status == "\"NotPresent\"")
	{
		return MitigationPresence::NotPresent;
	}
	if (status == "\"NotApplicable\"")
	{
		return MitigationPresence::NotApplicable;
	}if (status == "\"NotImplemented\"")
	{
		return MitigationPresence::NotImplemented;
	}
	return MitigationPresence::Unknown;
}

void ParseOutput(const char* s, MitigationInfo& mi)
{
	std::string str(s);
	auto v = Split(str, '\n');
	mi.DynamicBase = MitigationPresence::Unknown;
	mi.ASLR = MitigationPresence::Unknown;
	mi.HighEntropyVA = MitigationPresence::Unknown;
	mi.ForceIntegrity = MitigationPresence::Unknown;
	mi.Isolation = MitigationPresence::Unknown;
	mi.NX = MitigationPresence::Unknown;
	mi.SEH = MitigationPresence::Unknown;
	mi.CFG = MitigationPresence::Unknown;
	mi.RFG = MitigationPresence::Unknown;
	mi.SafeSEH = MitigationPresence::Unknown;
	mi.GS = MitigationPresence::Unknown;
	mi.Authenticode = MitigationPresence::Unknown;
	mi.DotNET = MitigationPresence::Unknown;
	for (auto& x : v)
	{
		auto v2 = Split(x, ':');
		if (v2.size() != 2) continue;
		auto name = Trim(v2[0]);
		auto status = Trim(v2[1]);
		const auto eStatus = ToMP(status);

		if (name == "Dynamic Base")
		{
			mi.DynamicBase = eStatus;
		}
		else if (name == "ASLR")
		{
			mi.ASLR = eStatus;
		}
		else if (name == "High Entropy VA")
		{
			mi.HighEntropyVA = eStatus;
		}
		else if (name == "Force Integrity")
		{
			mi.ForceIntegrity = eStatus;
		}
		else if (name == "Isolation")
		{
			mi.Isolation = eStatus;
		}
		else if (name == "NX")
		{
			mi.NX = eStatus;
		}
		else if (name == "SEH")
		{
			mi.SEH = eStatus;
		}
		else if (name == "CFG")
		{
			mi.CFG = eStatus;
		}
		else if (name == "RFG")
		{
			mi.RFG = eStatus;
		}
		else if (name == "SafeSEH")
		{
			mi.SafeSEH = eStatus;
		}
		else if (name == "GS")
		{
			mi.GS = eStatus;
		}
		else if (name == "Authenticode")
		{
			mi.Authenticode = eStatus;
		}
		else if (name == ".NET")
		{
			mi.DotNET = eStatus;
		}
	}
}


BOOL DoWinCheckSec(const wchar_t* modPath, MitigationInfo& mi)
{
	HANDLE				read, write;
	SECURITY_ATTRIBUTES	sa;
	STARTUPINFOW 		si;
	PROCESS_INFORMATION	pi;
	DWORD				len;
	const DWORD timeout = 1000;
	char buf[2048] = { 0 };
	const DWORD size = sizeof buf;

	sa.nLength = sizeof(sa);
	sa.lpSecurityDescriptor = 0;
	sa.bInheritHandle = TRUE;

	if (!CreatePipe(&read, &write, &sa, 0))
	{
		dprintf("%ls: CreatePipe failed\n", modPath);
		return FALSE;
	}

	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES;
	if (stdout) si.hStdOutput = write;
	// if (stderr) si.hStdError = write;
	if (!winCheckSecPath)
	{
		winCheckSecPath = std::wstring(L"winchecksec");
	}
	const auto cmdLen = winCheckSecPath.value().length() + wcslen(modPath) + 4;
	const std::unique_ptr<wchar_t[]> cmd(new wchar_t[cmdLen]);
	swprintf_s(cmd.get(), cmdLen, L"%ls \"%ls\"", winCheckSecPath.value().c_str(), modPath);

	// dprintf("cmd: %d,%ls\n", cmdLen, cmd.get());

	if (!CreateProcessW(NULL, cmd.get(), NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
	{
		dprintf("CreateProcessW %ls failed: %lu\n", cmd.get(), GetLastError());
		return FALSE;
	}

	while (WaitForSingleObject(pi.hProcess, timeout) != WAIT_OBJECT_0) {}

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	if (!PeekNamedPipe(read, NULL, 0, NULL, &len, NULL))
	{
		dprintf("%ls: PeekNamedPipe failed: %lu\n", modPath, GetLastError());
		return FALSE;
	}

	memset(buf, '\0', size);

	if (len > 0 && !ReadFile(read, buf, size - 1, &len, NULL))
	{
		dprintf("%ls: ReadFile failed: %lu\n", modPath, GetLastError());
		return FALSE;
	}
	CloseHandle(read);
	CloseHandle(write);
	ParseOutput(buf, mi);
	return TRUE;
}

const char* MPToStr(MitigationPresence p, bool showYes = true, bool showNo = true)
{
#define YES "Y"
#define NO "N"
#define UNKNOWN "U"
#define SPACE " "
	switch (p)
	{
	case MitigationPresence::Present:
		return showYes ? YES : SPACE;
	case MitigationPresence::NotPresent:
		return showNo ? NO : SPACE;
	case MitigationPresence::NotApplicable:
		return showNo ? NO : SPACE;
	case MitigationPresence::NotImplemented:
		return showNo ? NO : SPACE;
	case MitigationPresence::Unknown:
		return UNKNOWN;
	}
	return UNKNOWN;
#undef YES
#undef NO
#undef UNKNOWN
}

std::string ToLowerA(std::string s) {
	std::ranges::transform(s, s.begin(), [](unsigned char c)
		{
			return static_cast<char>(std::tolower(c));
		});
	return s;
}

std::wstring ToLowerW(std::wstring s) {
	std::ranges::transform(s, s.begin(), [](const wchar_t c)
		{
			if (L'A' <= c && c <= L'Z') return static_cast<wchar_t>(c - L'A' + L'a');
			return c;
		});
	return s;
}

wchar_t* MultiByteToWideCharWrap(const char* s, const int len)
{
	auto l = MultiByteToWideChar(CP_ACP, 0, s, len, NULL, 0);
	wchar_t* buf = nullptr;

	if (l)
	{
		buf = static_cast<wchar_t*>(malloc(l + 1));
		if (!buf)return nullptr;
		buf[l] = '\0';
		if (!MultiByteToWideChar(CP_ACP, 0, s, len, buf, l + 1))
		{
			return nullptr;
		}
	}
	return buf;
}
