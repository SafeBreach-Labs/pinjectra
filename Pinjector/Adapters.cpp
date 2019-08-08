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

#include "WritingTechniques.h"

//////////////////////////////////////////
// ComplexToAdvanceMemoryWriter Adapter //
//////////////////////////////////////////

ComplexToMutableAdvanceMemoryWriter::~ComplexToMutableAdvanceMemoryWriter() {

}

PINJECTRA_PACKET* ComplexToMutableAdvanceMemoryWriter::eval_and_write(TARGET_PROCESS* target, TStrDWORD64Map& params) {
	PINJECTRA_PACKET* payload_output;
	RUNTIME_MEM_ENTRY* writer_output;

	// Evaulate Payload
	payload_output = this->m_payload->eval(params);

	// Update Writer
	this->m_writer->SetBuffer(payload_output->buffer);
	this->m_writer->SetBufferSize(payload_output->buffer_size);

	// Write!
	writer_output = this->m_writer->writeto(target->process, 0);

	// Hijack Payload Output
	free(payload_output->buffer);
	payload_output->buffer = writer_output->addr;
	payload_output->buffer_size = writer_output->tot_write;

	return payload_output;
}
