#include <iostream>
#include <Windows.h>
#include <winnt.h> // Required for callback function

LPVOID primaryFiber = NULL;
LPVOID secondaryFiber = NULL;
DWORD flsIndexNumber = 0;

void MyCallbackFunction(PVOID lpFlsData)
{
    std::cout << "\t\t[!] Hello from inside callback function\n";

    char flsData[8] = "";
    memcpy(&flsData, lpFlsData, 0x08);

    std::cout << "\t\t[!] Parameter provided to callback function (i.e. FLS Slot value) equals: " << flsData << "\n\n";
}

void SecondaryFiberFunc()
{
    int ch = 0;

    while (true)
    {
        std::cout << "\n[!] Executing as secondary Fiber. Waiting for input ...\n";
        std::cout << "\t[!] Options:\n";
        std::cout << "\t[!] Enter 's' to switch to primary fiber\n";
        std::cout << "\t[!] Enter 'f' to trigger user-defined callback\n";
        std::cout << "\t[!] Enter 'e' to delete current Fiber and exit\n";

        // Wait for user input
        ch = std::cin.get();
        std::cin.ignore(1, 10); // Ignore until 'Enter' i.e. 10 in ASCII
        // std::cout << ch << "\n";
        while (ch != 101 && ch != 102 && ch != 115)
        {
            std::cout << "\t[+] Invalid option provided, please enter valid option\n";
            ch = std::cin.get();
            std::cin.ignore(1, 10);
        }

        if (ch == 102) // 'f' (lowercase) in ASCII
        {
            std::cout << "\t[+] Freeing FLS index to trigger callback function\n";
            if (!FlsFree(flsIndexNumber))
            {
                std::cout << "\t\t[!] User defined callback function already freed\n";
            }
        }
        else if (ch == 101) // 'e' (lowercase) in ASCII
        {
            std::cout << "\t[+] Exiting gracefully using DeleteFiber()\n";
            // If the currently running fiber calls DeleteFiber, its thread calls ExitThread and terminates 
            DeleteFiber(secondaryFiber);
        }
        else if (ch == 115) // 's' (lowercase) in ASCII
        {
            std::cout << "\t[+] Switching to primaryFiber\n";
            SwitchToFiber(primaryFiber);
        }
    }
}

void ScheduleFibers()
{

    bool first = true;

    // Get the current process ID
    DWORD tid = GetCurrentThreadId();

    // Print the PID
    std::cout << "[!] Current Thread ID: " << tid << std::endl;

    // Convert current Thread to a Fiber
    std::cout << "[+] Converting thread to Fiber\n";
    primaryFiber = ConvertThreadToFiber(NULL);

    // Create a second fiber
    secondaryFiber = CreateFiber(0, (LPFIBER_START_ROUTINE)(void*)SecondaryFiberFunc, 0);

    // Allocate some Fiber Local Storage (FLS) for primary fiber and set FLS value
    const char* flsValue = "myValue";
    std::cout << "[+] Setting callback for primary Fiber & FLS Slot value\n";
    flsIndexNumber = FlsAlloc((PFLS_CALLBACK_FUNCTION)MyCallbackFunction);
    FlsSetValue(flsIndexNumber, (PVOID)flsValue);
    std::cout << "[!] FLS index number: " << flsIndexNumber << "\n";
    std::cout << "[!] FLS slot value: " << flsValue << "\n";
    std::cout << "[!] Address of MyCallbackFunction: 0x" << MyCallbackFunction << "\n\n";

    // Execute fiber switching loop.
    int ch = 0;
    while (true)
    {
        std::cout << "\n[!] Executing as primary Fiber. Waiting for input ...\n";
        std::cout << "\t[!] Options:\n";
        std::cout << "\t[!] Enter 's' to switch to secondary fiber\n";
        std::cout << "\t[!] Enter 'f' to trigger user-defined callback\n";
        std::cout << "\t[!] Enter 'e' to delete current Fiber and exit\n";

        // Wait for user input
        ch = std::cin.get();
        std::cin.ignore(1, 10); // Ignore until 'Enter' i.e. 10 in ASCII
        // std::cout << ch << "\n";
        while (ch != 101 && ch != 102 && ch != 115)
        {
            std::cout << "\t[-] Invalid option provided, please enter valid option\n";
            ch = std::cin.get();
            std::cin.ignore(1, 10);
        }

        if (ch == 102) // 'f' (lowercase) in ASCII
        {
            std::cout << "\t[+] Freeing FLS index to trigger callback function\n";
            if (!FlsFree(flsIndexNumber))
            {
                std::cout << "\t\t[!] User defined callback function already freed\n";
            }
        }
        else if (ch == 101) // 'e' (lowercase) in ASCII
        {
            std::cout << "\t[+] Exiting gracefully using DeleteFiber()\n";
            // If the currently running fiber calls DeleteFiber, its thread calls ExitThread and terminates 
            DeleteFiber(primaryFiber);
        }
        else if (ch == 115) // 's' (lowercase) in ASCII
        {
            std::cout << "\t[+] Switching to secondaryFiber\n";
            SwitchToFiber(secondaryFiber);
        }
    }

}

int main()
{

    printf(R"EOF(

______           _       ______ _ _               
| ___ \         (_)      |  ___(_) |              
| |_/ / __ _ ___ _  ___  | |_   _| |__   ___ _ __ 
| ___ \/ _` / __| |/ __| |  _| | | '_ \ / _ \ '__|
| |_/ / (_| \__ \ | (__  | |   | | |_) |  __/ |   
\____/ \__,_|___/_|\___| \_|   |_|_.__/ \___|_|   
                                                  
                                                  
)EOF");
    printf("\n\n");

    // Get the current process ID
    DWORD pid = GetCurrentProcessId();

    // Print the PID
    std::cout << "[!] Current process ID: " << pid << std::endl;

    DWORD tid = 0;
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ScheduleFibers, 0, 0, &tid);
    WaitForSingleObject(hThread, INFINITE);
    return 0;
}


