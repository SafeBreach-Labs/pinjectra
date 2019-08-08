// BASED ON
// https://github.com/odzhan/injection/tree/master/spooler
// https://modexp.wordpress.com/2019/03/07/process-injection-print-spooler/

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
#include <vector>
#include <string>

// Local Include's
#include "ExecutionTechnique.h"
#include "WritingTechniques.h"

// Macros
#define NT_SUCCESS(x) ((x)>=0)

#define NTFUNC(f,fname,def) typedef NTSTATUS (* t##f) def;\
t##f f=(t##f)GetProcAddress(GetModuleHandleA("ntdll"),fname)

// Datatypes
typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation = 0,
	SystemProcessorInformation = 1,             // obsolete...delete
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemPathInformation = 4,
	SystemProcessInformation = 5,
	SystemCallCountInformation = 6,
	SystemDeviceInformation = 7,
	SystemProcessorPerformanceInformation = 8,
	SystemFlagsInformation = 9,
	SystemCallTimeInformation = 10,
	SystemModuleInformation = 11,
	SystemLocksInformation = 12,
	SystemStackTraceInformation = 13,
	SystemPagedPoolInformation = 14,
	SystemNonPagedPoolInformation = 15,
	SystemHandleInformation = 16,
	SystemObjectInformation = 17,
	SystemPageFileInformation = 18,
	SystemVdmInstemulInformation = 19,
	SystemVdmBopInformation = 20,
	SystemFileCacheInformation = 21,
	SystemPoolTagInformation = 22,
	SystemInterruptInformation = 23,
	SystemDpcBehaviorInformation = 24,
	SystemFullMemoryInformation = 25,
	SystemLoadGdiDriverInformation = 26,
	SystemUnloadGdiDriverInformation = 27,
	SystemTimeAdjustmentInformation = 28,
	SystemSummaryMemoryInformation = 29,
	SystemMirrorMemoryInformation = 30,
	SystemPerformanceTraceInformation = 31,
	SystemObsolete0 = 32,
	SystemExceptionInformation = 33,
	SystemCrashDumpStateInformation = 34,
	SystemKernelDebuggerInformation = 35,
	SystemContextSwitchInformation = 36,
	SystemRegistryQuotaInformation = 37,
	SystemExtendServiceTableInformation = 38,
	SystemPrioritySeperation = 39,
	SystemVerifierAddDriverInformation = 40,
	SystemVerifierRemoveDriverInformation = 41,
	SystemProcessorIdleInformation = 42,
	SystemLegacyDriverInformation = 43,
	SystemCurrentTimeZoneInformation = 44,
	SystemLookasideInformation = 45,
	SystemTimeSlipNotification = 46,
	SystemSessionCreate = 47,
	SystemSessionDetach = 48,
	SystemSessionInformation = 49,
	SystemRangeStartInformation = 50,
	SystemVerifierInformation = 51,
	SystemVerifierThunkExtend = 52,
	SystemSessionProcessInformation = 53,
	SystemLoadGdiDriverInSystemSpace = 54,
	SystemNumaProcessorMap = 55,
	SystemPrefetcherInformation = 56,
	SystemExtendedProcessInformation = 57,
	SystemRecommendedSharedDataAlignment = 58,
	SystemComPlusPackage = 59,
	SystemNumaAvailableMemory = 60,
	SystemProcessorPowerInformation = 61,
	SystemEmulationBasicInformation = 62,
	SystemEmulationProcessorInformation = 63,
	SystemExtendedHandleInformation = 64,
	SystemLostDelayedWriteInformation = 65,
	SystemBigPoolInformation = 66,
	SystemSessionPoolTagInformation = 67,
	SystemSessionMappedViewInformation = 68,
	SystemHotpatchInformation = 69,
	SystemObjectSecurityMode = 70,
	SystemWatchdogTimerHandler = 71,
	SystemWatchdogTimerInformation = 72,
	SystemLogicalProcessorInformation = 73,
	SystemWow64SharedInformation = 74,
	SystemRegisterFirmwareTableInformationHandler = 75,
	SystemFirmwareTableInformation = 76,
	SystemModuleInformationEx = 77,
	SystemVerifierTriageInformation = 78,
	SystemSuperfetchInformation = 79,
	SystemMemoryListInformation = 80,
	SystemFileCacheInformationEx = 81,
	MaxSystemInfoClass = 82  // MaxSystemInfoClass should always be the last enum

} SYSTEM_INFORMATION_CLASS;

typedef enum _OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation,
	ObjectTypeInformation
} OBJECT_INFORMATION_CLASS;

// this structure is derived from TP_CALLBACK_ENVIRON_V3,
// but also includes two additional values. one to hold
// the callback function and the other is a callback parameter
typedef struct _TP_CALLBACK_ENVIRONX {
	DWORD64   Version;
	DWORD64   Pool;
	DWORD64   CleanupGroup;
	DWORD64   CleanupGroupCancelCallback;
	DWORD64   RaceDll;
	DWORD64   ActivationContext;
	DWORD64   FinalizationCallback;
	DWORD64   Flags;
	DWORD64   CallbackPriority;
	DWORD64   Size;
	DWORD64   Callback;
	DWORD64   CallbackParameter;
} TP_CALLBACK_ENVIRONX, * PTP_CALLBACK_ENVIRONX;

typedef VOID* POBJECT;

typedef struct _SYSTEM_HANDLE {
	ULONG		uIdProcess;
	UCHAR		ObjectType;    // OB_TYPE_* (OB_TYPE_TYPE, etc.)
	UCHAR		Flags;         // HANDLE_FLAG_* (HANDLE_FLAG_INHERIT, etc.)
	USHORT		Handle;
	POBJECT		pObject;
	ACCESS_MASK	GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_NAME_INFORMATION
{
	UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;

typedef struct
{
	HANDLE hp;
	std::vector<std::wstring> ports;
	DWORD pid;
	BYTE* payload;
	DWORD64 payloadSize;
} process_info;

typedef struct _tp_param_t {
	DWORD64   Callback;
	DWORD64   CallbackParameter;
} tp_param;

// Classes
class CodeViaALPC :
	public ExecutionTechnique
{
public:
	// Constructor & Destructor
	CodeViaALPC(AdvanceMemoryWriter* memwriter)
		:m_memwriter(memwriter) { }
	~CodeViaALPC();

	// Methods
	boolean inject(DWORD pid, DWORD tid);

private:
	// Methods
	BOOL IsValidCBE(HANDLE hProcess, PTP_CALLBACK_ENVIRONX cbe);
	DWORD64 GetALPCPorts(process_info* pi);
	BOOL ALPC_Connect(std::wstring path);
	BOOL ALPC_deploy(process_info* pi, LPVOID ds, PTP_CALLBACK_ENVIRONX cbe);
	BOOL FindCallback(process_info* pi, LPVOID BaseAddress, SIZE_T RegionSize);
	BOOL ScanProcess(process_info* pi);

protected:
	// Members
	AdvanceMemoryWriter* m_memwriter;

};

