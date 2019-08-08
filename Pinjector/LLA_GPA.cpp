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

#include "LLA_GPA.h"
#include "HookProcProvider.h"

LoadLibraryA_GetProcAddress::~LoadLibraryA_GetProcAddress()
{
}

RUNTIME_PROC_ENTRY* LoadLibraryA_GetProcAddress::provide() {
	HMODULE ret_module;
	FARPROC ret_proc;
	RUNTIME_PROC_ENTRY* ret_entry;

	ret_module = LoadLibraryA(this->m_lpLibFileName);
	if (ret_module == NULL)
		return nullptr;

	ret_proc = GetProcAddress(ret_module, this->m_lpProcName);
	if (ret_proc == NULL)
		return nullptr;

	ret_entry = (RUNTIME_PROC_ENTRY*)malloc(sizeof(RUNTIME_PROC_ENTRY));

	if (ret_entry == NULL)
		return NULL;

	// Fill in
	ret_entry->module = ret_module;
	ret_entry->proc = ret_proc;

	return ret_entry;
}
