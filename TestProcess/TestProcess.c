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

#define WINVER 0x0A00
#define _WIN32_WINNT 0x0A00

#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

// Message Loop as ThreadProc Callback function
DWORD WINAPI message_loop(_In_ LPVOID lpParameter) {
	MSG msg;
	BOOL bRet;
	printf("Message Loop Thread ID = %d\n", GetCurrentThreadId());

	while ((bRet = GetMessage(&msg, NULL, 0, 0)) != 0) {
		if (bRet == -1) {
			// handle the error and possibly exit
		}
		else {
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}

	// Return the exit code to the system.
	return msg.wParam;
}

#if 0
int protection_up() {
	PROCESS_MITIGATION_DYNAMIC_CODE_POLICY policy1;
	policy1.ProhibitDynamicCode = 1;
	policy1.AllowThreadOptOut = 0;
	policy1.AllowRemoteDowngrade = 0;
	policy1.AuditProhibitDynamicCode = 0;
	policy1.ReservedFlags = 0;

	if (!SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &policy1, sizeof(policy1))) {
		printf("Policy PROCESS_MITIGATION_DYNAMIC_CODE_POLICY change error: 0x%08x\n", GetLastError());
		return 0;
	}

	PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY policy2;
	policy2.EnableControlFlowGuard = 1;
	policy2.EnableExportSuppression = 0;  // or else we'll need GetProcAddress for every function we want to invoke...
	policy2.StrictMode = 1;
	policy2.ReservedFlags = 0;

	if (!SetProcessMitigationPolicy(ProcessControlFlowGuardPolicy, &policy2, sizeof(policy2))) {
		printf("Policy PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY change error: 0x%08x\n", GetLastError());
		return 0;
	}

	PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY policy3;
	policy3.RaiseExceptionOnInvalidHandleReference = 1;
	policy3.HandleExceptionsPermanentlyEnabled = 1;
	policy3.ReservedFlags = 0;

	if (!SetProcessMitigationPolicy(ProcessStrictHandleCheckPolicy, &policy3, sizeof(policy3))) {
		printf("Policy PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY change error: 0x%08x\n", GetLastError());
		return 0;
	}

	PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY policy5;
	policy5.DisableExtensionPoints = 1;
	policy5.ReservedFlags = 0;

	if (!SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy, &policy5, sizeof(policy5))) {
		printf("Policy PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY change error: 0x%08x\n", GetLastError());
		return 0;
	}

	PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY policy6;
	memset(&policy6, 0, sizeof(policy6));
	policy6.MicrosoftSignedOnly = 1;
	policy6.ReservedFlags = 0;

	if (!SetProcessMitigationPolicy(ProcessSignaturePolicy, &policy6, sizeof(policy6))) {
		printf("Policy PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY change error: 0x%08x\n", GetLastError());
		return 0;
	}

	PROCESS_MITIGATION_FONT_DISABLE_POLICY policy7;
	memset(&policy7, 0, sizeof(policy7));
	policy7.DisableNonSystemFonts = 1;
	policy7.AuditNonSystemFontLoading = 0;
	policy7.ReservedFlags = 0;

	if (!SetProcessMitigationPolicy(ProcessFontDisablePolicy, &policy7, sizeof(policy7))) {
		printf("Policy PROCESS_MITIGATION_FONT_DISABLE_POLICY change error: 0x%08x\n", GetLastError());
		return 0;
	}

	PROCESS_MITIGATION_IMAGE_LOAD_POLICY policy8;
	memset(&policy8, 0, sizeof(policy8));
	policy8.NoRemoteImages = 1;
	policy8.NoLowMandatoryLabelImages = 1;
	policy8.PreferSystem32Images = 1;
	policy8.ReservedFlags = 0;

	if (!SetProcessMitigationPolicy(ProcessImageLoadPolicy, &policy8, sizeof(policy8))) {
		printf("Policy PROCESS_MITIGATION_IMAGE_LOAD_POLICY change error: 0x%08x\n", GetLastError());
		return 0;
	}

	// Error 0x00000057 The parameter is incorrect.
	PROCESS_MITIGATION_ASLR_POLICY policy9;
	memset(&policy9, 0, sizeof(policy9));
	policy9.EnableBottomUpRandomization = 1;
	policy9.EnableForceRelocateImages = 1;
	policy9.EnableHighEntropy = 1;
	policy9.DisallowStrippedImages = 1;
	policy9.ReservedFlags = 0;

	if (!SetProcessMitigationPolicy(ProcessASLRPolicy, &policy9, sizeof(policy9))) {
		printf("Policy PROCESS_MITIGATION_ASLR_POLICY change error: 0x%08x\n", GetLastError());
		return 0;
	}

	return 1;
}

int protection_down() {
	return 1;
}
#endif

void banner() {
	int i;
	unsigned char banner_txt[] = {
	  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x5f, 0x20, 0x2e, 0x5f,
	  0x20, 0x20, 0x5f, 0x20, 0x2c, 0x20, 0x5f, 0x20, 0x2e, 0x5f, 0x0a, 0x20,
	  0x20, 0x20, 0x20, 0x20, 0x20, 0x28, 0x5f, 0x20, 0x27, 0x20, 0x28, 0x20,
	  0x60, 0x20, 0x20, 0x29, 0x5f, 0x20, 0x20, 0x2e, 0x5f, 0x5f, 0x29, 0x0a,
	  0x20, 0x20, 0x20, 0x20, 0x28, 0x20, 0x28, 0x20, 0x20, 0x28, 0x20, 0x20,
	  0x20, 0x20, 0x29, 0x20, 0x20, 0x20, 0x60, 0x29, 0x20, 0x20, 0x29, 0x20,
	  0x5f, 0x29, 0x0a, 0x20, 0x20, 0x20, 0x28, 0x5f, 0x5f, 0x20, 0x28, 0x5f,
	  0x20, 0x20, 0x20, 0x28, 0x5f, 0x20, 0x2e, 0x20, 0x5f, 0x29, 0x20, 0x5f,
	  0x29, 0x20, 0x2c, 0x5f, 0x5f, 0x29, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20,
	  0x20, 0x20, 0x60, 0x7e, 0x7e, 0x60, 0x5c, 0x20, 0x27, 0x20, 0x2e, 0x20,
	  0x2f, 0x60, 0x7e, 0x7e, 0x60, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	  0x20, 0x2c, 0x3a, 0x3a, 0x3a, 0x20, 0x3b, 0x20, 0x20, 0x20, 0x3b, 0x20,
	  0x3a, 0x3a, 0x3a, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x27,
	  0x3a, 0x3a, 0x3a, 0x3a, 0x3a, 0x3a, 0x3a, 0x3a, 0x3a, 0x3a, 0x3a, 0x3a,
	  0x3a, 0x3a, 0x3a, 0x27, 0x0a, 0x20, 0x5f, 0x6a, 0x67, 0x73, 0x5f, 0x5f,
	  0x5f, 0x5f, 0x5f, 0x5f, 0x2f, 0x5f, 0x20, 0x5f, 0x5f, 0x20, 0x5c, 0x5f,
	  0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x0a, 0x7c, 0x20,
	  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	  0x20, 0x20, 0x7c, 0x0a, 0x7c, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	  0x54, 0x45, 0x53, 0x54, 0x20, 0x50, 0x52, 0x4f, 0x43, 0x45, 0x53, 0x53,
	  0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x7c, 0x0a, 0x7c, 0x5f,
	  0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f,
	  0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f, 0x5f,
	  0x5f, 0x5f, 0x7c, 0x0a, 0x0a
	};

	for (i = 0; i < 293; i++)
		printf("%c", banner_txt[i]);

	return ;
}

int main(int argc, char** argv) {
	banner();

#if 0
	if (argc > 1) {
		if (!strcmp(argv[1], "/PROT_UP")) {
			printf("Process Protection Up ...\n");
			protection_up();
		}
		if (!strcmp(argv[1], "/PROT_DOWN")) {
			printf("Process Protection Down ...\n");
			protection_down();
		}
		if (!strcmp(argv[1], "/?")) {
			printf("usage: %s [/PROT_UP | /PROT_DOWN]\n", argv[0]);
			return 0;
		}
	}
#endif

	printf("Creating Message Loop ...\n");

	CreateThread(NULL, 0, message_loop, 0, 0, NULL);

	printf("Putting Process into Alterable State ...\n");

		while (1) {
			printf("PID=%d, TID=%d -- In Alertable State!\n", GetCurrentProcessId(), GetCurrentThreadId());
			SleepEx(10000, TRUE);
		}

	return 0;
}
