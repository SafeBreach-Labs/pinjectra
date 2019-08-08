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
#include <map>
#include <string>
#include <iostream>

#include <windows.h>

// Local Include's
#include "PinjectraPacket.h"

// Consts
#ifndef PAYLOAD4_SIZE
#define PAYLOAD4_SIZE 75
#endif

#ifndef PAYLOAD5_SIZE
#define PAYLOAD5_SIZE 107
#endif


// Classes
class DynamicPayload
{
public:
	virtual PINJECTRA_PACKET* eval(TStrDWORD64Map &runtime_parameters) = 0;
};

///////////////////////////////
// Payload with Substitution //
///////////////////////////////

class _PAYLOAD_5 :
	public DynamicPayload
{
public:
	PINJECTRA_PACKET* eval(TStrDWORD64Map& runtime_parameters);
};

class _PAYLOAD_4 :
	public DynamicPayload
{
public:
	PINJECTRA_PACKET* eval(TStrDWORD64Map& runtime_parameters);
};

////////////////
// ROP Chains //
////////////////

class _ROP_CHAIN_1 :
	public DynamicPayload
{
public:
	PINJECTRA_PACKET* eval(TStrDWORD64Map& runtime_parameters);
};

class _ROP_CHAIN_2 :
	public DynamicPayload
{
public:
	PINJECTRA_PACKET* eval(TStrDWORD64Map& runtime_parameters);
};
