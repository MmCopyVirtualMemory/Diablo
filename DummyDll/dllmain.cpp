// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <iostream>

/*

*/


//https://stackoverflow.com/questions/1279292/how-do-i-create-a-win32-dll-without-a-dependency-on-the-c-runtime
uint64_t APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
                     )
{
    std::cout << "HELLO FROM DLLMAIN!" << std::endl;
    while (!GetAsyncKeyState(VK_END)) 
    {
        Sleep(1);
    }


    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: 
    {
        std::cout << "HELLO FROM ATTACH!" << std::endl;
        //std::cout << URLDownloadToFile << std::endl;
        
        Sleep(2000);
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

