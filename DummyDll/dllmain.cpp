// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <iostream>

using U64 = unsigned long long;
using U32 = unsigned long;



//https://stackoverflow.com/questions/1279292/how-do-i-create-a-win32-dll-without-a-dependency-on-the-c-runtime
uint64_t APIENTRY DllMain(U64 hModule,
    U32  ul_reason_for_call,
    U64 lpReserved
                     )
{
    
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: 
    {

        MessageBoxA(0, "Hello Lil Bro", "Hi!", 0);
        



    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

