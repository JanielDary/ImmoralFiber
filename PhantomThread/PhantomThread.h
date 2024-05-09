#pragma once

#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <strsafe.h>
#include <string>

#define INITIAL_THREAD 0x0400 // SameTebFlags mask for InitialThread - https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/teb/sametebflags.htm
#define HAS_FIBER_DATA 0X0004 // USHORT HasFiberData mask

// Exported func from PhantomThreadPayload.dll
typedef int(WINAPI* PAYLOAD_FUNC)(LPVOID);
PAYLOAD_FUNC PayloadFunc;
HMODULE hModule;

bool runPayloadMultipleTimes = true;
LPVOID primaryFiber = NULL;
LPVOID secondaryFiber = NULL;
LPVOID dummyFiber = NULL;

//
// Pseudo Fiber struct rebuilt from IDA KernelBase!CreateFiberEx
//
struct Fiber
{
	PVOID FiberData; // 0x00
	struct _EXCEPTION_REGISTRATION_RECORD* ExceptionList; // +0x08
	PVOID StackBase; // +0x10
	PVOID StackLimit; // +0x18
	PVOID DeallocationStack; // +0x20
	CONTEXT FiberContext;
	PVOID Wx86Tib;
	struct  _ACTIVATION_CONTEXT_STACK* ActivationContextStackPointer;
	PVOID FlsData;
	ULONG GuaranteedStackBytes;
	ULONG TebFlags;
	uint64_t XoredCookie; // Xored stack based cookie, used as a sanity check when switching fibers in KernelBase!SwitchToFiber
	PVOID ShadowStack;
};