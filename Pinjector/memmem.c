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

#include "memmem.h"

// https://stackoverflow.com/questions/52988769/writing-own-memmem-for-windows
void* memmem(const void* haystack, size_t haystack_len, const void* const needle, const size_t needle_len)
{
	if (haystack == NULL) return NULL; // or assert(haystack != NULL);
	if (haystack_len == 0) return NULL;
	if (needle == NULL) return NULL; // or assert(needle != NULL);
	if (needle_len == 0) return NULL;

	for (const char* h = haystack;
		haystack_len >= needle_len;
		++h, --haystack_len) {
		if (!memcmp(h, needle, needle_len)) {
			return h;
		}
	}
	return NULL;
}
