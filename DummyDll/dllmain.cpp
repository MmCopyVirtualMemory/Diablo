// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <iostream>
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    std::cout << "HELLO FROM DLLMAIN!" << std::endl;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: 
    {
        std::cout << "HELLO FROM ATTACH!" << std::endl;
        Sleep(2000);
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

