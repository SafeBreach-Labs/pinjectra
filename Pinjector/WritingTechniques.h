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

#pragma once

// Standard Include's
#include <iostream>
#include <map>
#include <string.h>

#include <windows.h>

// Local Include's
#include "PinjectraPacket.h"
#include "DynamicPayloads.h"

// Data Types
typedef struct {
	HANDLE process;
	HANDLE thread;
	LPVOID addr;
	LPVOID entry_point;
	SIZE_T tot_write;
	SIZE_T tot_alloc;
} RUNTIME_MEM_ENTRY;

typedef struct {
	HANDLE process;
	HANDLE thread;
	DWORD pid;
	DWORD tid;
} TARGET_PROCESS;

////////////////////
// Writer Classes //
////////////////////

class SimpleMemoryWriter
{
public:
	virtual RUNTIME_MEM_ENTRY* write(DWORD pid, DWORD tid) = 0;
};

class AdvanceMemoryWriter
{
public:
	virtual RUNTIME_MEM_ENTRY* writeto(HANDLE process_handle, SIZE_T additional_mem_space) = 0;
};

class ComplexMemoryWriter
{
public:
	virtual PINJECTRA_PACKET* eval_and_write(TARGET_PROCESS* target, TStrDWORD64Map &params) = 0;
};

// Base Class
class MutableAdvanceMemoryWriter :
	public AdvanceMemoryWriter
{
public:
	void* GetBuffer(void) const { return(m_buf); };
	void SetBuffer(void *buf) { m_buf = buf; };
	size_t GetBufferSize(void) const { return(m_nbyte); };
	void SetBufferSize(size_t nbyte) { m_nbyte = nbyte; };

protected:
	void* m_buf;
	size_t m_nbyte;
};

/////////////////////
// Adapter Classes //
/////////////////////

class ComplexToMutableAdvanceMemoryWriter :
	public ComplexMemoryWriter
{
public:
	// Constructor & Destructor
	ComplexToMutableAdvanceMemoryWriter(DynamicPayload* payload, MutableAdvanceMemoryWriter* writer) :
		m_payload(payload),
		m_writer(writer) { }
	~ComplexToMutableAdvanceMemoryWriter();

	// Methods
	PINJECTRA_PACKET* eval_and_write(TARGET_PROCESS* target, TStrDWORD64Map& params);

protected:
	// Members
	DynamicPayload* m_payload;
	MutableAdvanceMemoryWriter* m_writer;
};
