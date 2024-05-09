#pragma once
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <iostream>
#include <cstdlib>  // for strtoul

#define STATUS_SUCCESS 0x00000000
#define Granulariy	0x10 // 0x10 for x64, 0x08 for x86. 
#define NtHeap		0xFFEEFFEE
#define SegmentHeap 0xDDEEDDEE

// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/teb/index.htm
#define HasFiberDataMask 0x004 // 6.0 and up.
#define TebOffset_SameTebFlags 0x17EE // 6.0 and onwards.
#define TibOffset_FiberData 0x20 // Pointer to current Fiber object

// For shellcode stored inside PoisonFiber resource.
PVOID shellcodeAddr = NULL;
DWORD shellcodeSize = NULL;

// https://github.com/wine-mirror/wine/blob/master/include/winternl.h
typedef struct _FLS_CALLBACK
{
	void* unknown;
	PFLS_CALLBACK_FUNCTION callback; // ~0 if NULL callback is set, NULL if FLS index is free.
} FLS_CALLBACK, * PFLS_CALLBACK;

typedef struct _FLS_INFO_CHUNK
{
	ULONG count;         // number of allocated FLS indexes in the chunk.
	FLS_CALLBACK callbacks[1];  // the size is 0x10 for chunk 0 and is twice as the previous chunk size for the rest.
} FLS_INFO_CHUNK, * PFLS_INFO_CHUNK;

typedef struct _GLOBAL_FLS_DATA
{
	FLS_INFO_CHUNK* flsCallbackChunks[8];
	LIST_ENTRY      flsListHead;
	ULONG           flsHighIndex;
} GLOBAL_FLS_DATA, * PGLOBAL_FLS_DATA;

struct CallbackTable
{
	DWORD pid;
	DWORD tid;
	std::vector<FLS_CALLBACK> callbackEntries; // Entries appear in order of index.
};

typedef struct _TEB_FLS_DATA
{
	LIST_ENTRY      flsListEntry;
	PVOID			flsDataChunks[8];
} TEB_FLS_DATA, * PTEB_FLS_DATA;

struct MyFlsLinkedEntries
{
	DWORD pid;
	DWORD tid;
	std::vector<LIST_ENTRY*> flsListEntries;
};

struct CallbackTableMeta
{
	PVOID callbackTableAddress;
	size_t nCallbackEntries;
	std::vector<FLS_CALLBACK> callbackEntries;
};

enum MY_THREADINFOCLASS
{
	ThreadBasicInformation,
};

typedef struct _THREAD_BASIC_INFORMATION
{
	NTSTATUS                ExitStatus;
	PVOID                   TebBaseAddress;
	CLIENT_ID               ClientId;
	KAFFINITY               AffinityMask;
	KPRIORITY               Priority;
	KPRIORITY               BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;


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
	TEB_FLS_DATA* FlsData;
	ULONG GuaranteedStackBytes;
	ULONG TebFlags;
	uint64_t XoredCookie; // Xored stack based cookie, used as a sanity check when switching fibers in KernelBase!SwitchToFiber
	PVOID ShadowStack;
};

struct TidPid
{
	DWORD tid;
	DWORD pid;
};

struct FiberInfo
{
	TidPid tidPid;
	bool current = false;
	Fiber fiberObject;
	uint64_t basepFiberCookie;
	std::vector<Fiber> dormantFibervector;
};

struct HeapEntryMeta
{
	DWORD pid; // Owning PID
	PVOID ntHeapAddr; // Allocation base of the heap block belongs to
	uint64_t heapBlockAddr;
	uint16_t heapBlockSize;
	uint8_t flags;
	uint8_t unusedBytes;
	SIZE_T requestedBytes; // Value given to RtlAllocateHeap. Calculated from heapBlockSize - unusedBytes.
};

// https://processhacker.sourceforge.io/doc/heapstruct_8h_source.html#l00005
// Not the actual structure, but has the same size.
typedef struct _HEAP_ENTRY
{
	PVOID PreviousBlockPrivateData;
	WORD Size;
	UCHAR Flags;
	UCHAR SmallTagIndex;
	WORD PreviousSize;
	UCHAR SegmentOffset;
	UCHAR UnusedBytes;
} HEAP_ENTRY, * PHEAP_ENTRY;

// https://processhacker.sourceforge.io/doc/heapstruct_8h_source.html#l00014
// First few fields of HEAP_SEGMENT, VISTA and above
typedef struct _HEAP_SEGMENT
{
	HEAP_ENTRY HeapEntry;
	ULONG SegmentSignature;
	ULONG SegmentFlags;
	LIST_ENTRY SegmentListEntry;
	struct _HEAP* Heap;
	PVOID BaseAddress;
	DWORD NumberOfPages;
	HEAP_ENTRY* FirstEntry;
	HEAP_ENTRY* LastValidEntry;
	DWORD NumberOfUnCommittedPages;
	// ...
} HEAP_SEGMENT, * PHEAP_SEGMENT;

// Imported functions
// NTDLL
typedef NTSTATUS(NTAPI* _NtQueryInformationThread)(
	IN		HANDLE				ThreadHandle,
	IN		MY_THREADINFOCLASS	ThreadInformationClass,
	IN OUT	PVOID				ThreadInformation,
	IN		ULONG				ThreadInformationLength,
	OUT		PULONG				ReturnLength OPTIONAL
	);

_NtQueryInformationThread NtQueryInfoThread;

typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
	IN	HANDLE				ProcessHandle,
	IN	PROCESSINFOCLASS	ProcessInformationClass,
	OUT	PVOID				ProcessInformation,
	IN	ULONG				ProcessInformationLength,
	OUT PULONG				ReturnLength OPTIONAL
	);

_NtQueryInformationProcess NtQueryInfoProcess;
