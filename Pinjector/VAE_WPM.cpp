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

#include "VAE_WPM.h"

VirtualAllocEx_WriteProcessMemory::~VirtualAllocEx_WriteProcessMemory()
{
}

RUNTIME_MEM_ENTRY* VirtualAllocEx_WriteProcessMemory::writeto(HANDLE process_handle, SIZE_T additional_mem_space)
{
	RUNTIME_MEM_ENTRY* ret_entry;
	BOOL writeprocmem_res;
	LPVOID addr;

	// Allocate
	addr = VirtualAllocEx(process_handle, NULL, this->m_nbyte+additional_mem_space, this->m_VirtualAllocEx_flAllocationType, this->m_VirtualAllocEx_flProtect);

	if (addr == NULL) {
		std::cerr << "VirtualAllocEx failed, error=" << GetLastError() << std::endl;
		return NULL;
	}

	writeprocmem_res = WriteProcessMemory(process_handle, addr, this->m_buf, this->m_nbyte, NULL);

	// Fill in
	ret_entry = (RUNTIME_MEM_ENTRY*)malloc(sizeof(RUNTIME_MEM_ENTRY));

	if (ret_entry == NULL)
		return NULL;

	ret_entry->thread = NULL;
	ret_entry->process = process_handle;
	ret_entry->addr = addr;
	ret_entry->entry_point = addr;
	ret_entry->tot_write = this->m_nbyte;
	ret_entry->tot_alloc = this->m_nbyte + additional_mem_space;

	return ret_entry;
}
