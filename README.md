# Diablo
Reverse engineering program using a driver for memory operations. 

**As of now I haven't decided to post the library that I use for process handling so I will leave that up to the reader to add themselves. As of now, the "Full" version development has been abandoned. I had it working with most of the same features but I decided that the lightweight console version better suited my needs so I never continued developing the full version**

# Features

## Driver Implementation
This can be easily rewritten for use with a driver. This way these features can be used on protected processes. For the past year or so I have used this for dumping protected processes to suit my reverse engineering needs. I have also injected numerous dlls into games protected by various anticheats. The code is designed to be modular so one could easily modify it to fit their needs such as the memory allocation for the DLL injection.
## Process Info
Use the command "info" to display all module info about the target process as shown below.

![image](https://user-images.githubusercontent.com/88007716/231944451-1ed299aa-f8fd-454d-873d-cc8367ee659b.png)

## Module Info
Use the command "mod" followed by the module name to display all of the info about a specified module within the target process.
* Module Base
* Module Size
* All Sections [Name, Start Address, Size, Info and Page Protection]

![image](https://user-images.githubusercontent.com/88007716/231944628-b932f2c8-ee89-40e0-951e-8cbb9438678c.png)

## Dump Module
Use the command "dump" followed by the module name you wish to dump. This will dump the module to the same directory as the executable. This can be useful when reversing anything packed. I have used this against a few protected processes to reverse engineer them.

![image](https://user-images.githubusercontent.com/88007716/231945194-f5661ef0-5718-4611-ac4a-f48d36298cba.png)

## Query Memory
Use the command "query" followed by the address that you wish to inquire about. The following information will be displayed from MEMORY_BASIC_INFORMATION.
* Allocation Base
* Allocation Protection
* Allocation Size
* Page Protection
* Allocation Type

![image](https://user-images.githubusercontent.com/88007716/231945352-38459f7e-41e7-4029-8485-25c69a29f24b.png)

## Inject DLL
Use the command "inject" followed by a number (injection method enumerator). I have spent the most time on this by far and because I am proud of the shellcode I wrote, I will write more about it. The memory allocation used is nothing special and it's made to be modular so I won't focus on that. The cherry on top of this post is the shellcode that I wrote to call the entry point (well actually which calls cruz's shellcode which calls the entry point). This shellcode uses what I will call a OnceHook (which I will attempt to coin as a real thing). This concept of a once hook is rather simple in thinking but slightly more challenging in application:
```
Swap a frequently called pointer to point at my shellcode.
The shellcode will preserve registers. The shellcode will be written so a pointer can be used to access data I set up before.
The shellcode will grab data from this pointer and set up for the call.
The shellcode calls the function provided in the structure using the data from the structure.
When the function returns, the shellcode will restore the values in the registers and rewrite the original value to the pointer as if nothing happened.
Finally the shellcode will jump to the original function.
```
This implementation is very handy and it has close to zero drawbacks. Firstly, the method of invocation can be universalized by using a function that almost every program uses (VirtualAlloc). I have yet to find a program worth injecting into that doesn't allocate some memory although if such program is found, it is very easy to find another pointer to do this with. Secondly, the program continues its execution as if nothing ever happened. The sequence in which events happen is very important for this to work properly but once it works, it does its job very well. Perhaps the biggest bonus of using a method like this is that it requires no extra thread creation or patching of a readonly section which makes it incredibly stealthy.

https://media.giphy.com/media/dT8aZn3iwR81FX2BeV/giphy.gif

Here is my implementation of a OnceHook:
```cpp
U64 RemoteCallLoadLibraryA(U64 lla_addr, std::string dll_path,
	U64 rwx_page, U64 freq_called_ptr, bool readonly = false)
{
	U64 path_ptr = AllocateMemory(dll_path.size(), PAGE_READWRITE);
	WriteRaw(path_ptr, dll_path.data(), dll_path.size());
	bool result = RemoteCallShellcode(lla_addr, path_ptr, rwx_page, freq_called_ptr, readonly);
	FreeMemory(path_ptr);
	return result;
}
bool RemoteCallShellcode(U64 func, U64 a1,
	U64 rwx_page, U64 freq_called_ptr = NULL, bool readonly = true)
{
	typedef struct SHELLCODE_DATA
	{
		U64 retn; //0x0
		struct
		{
			U64 a1; //0x8
		}args;
		U64 entry; //0x10
		U64 done; //0x18
		//hook data
		U64 ptr; //0x20
		U64 orig; //0x28
	};
	std::vector<BYTE> remote_call_shellcode =
	{
		0x48, 0x83, 0xEC, 0x28, //sub    rsp,0x28
		0x48, 0x89, 0x04, 0x24, //mov    QWORD PTR [rsp],rax
		0x48, 0x89, 0x4C, 0x24, 0x08, //mov    QWORD PTR [rsp+0x8],rcx
		0x4C, 0x89, 0x7C, 0x24, 0x10, //mov    QWORD PTR [rsp+0x10],r15
		0x4C, 0x89, 0x54, 0x24, 0x18, //mov    QWORD PTR [rsp+0x18],r10
		0x49, 0xBF, 0xFE, 0xCA, 0xBE, 0xBA, 0xEF, 0xBE, 0xAD, 0xDE, //movabs r15,0xdeadbeefbabecafe
		0x49, 0x8B, 0x47, 0x18, //mov    rax,QWORD PTR [r15+0x18]
		0x49, 0x8B, 0x4F, 0x08, //mov    rcx,QWORD PTR [r15+0x8]
		0x41, 0xFF, 0x57, 0x10, //call   QWORD PTR [r15+0x10]
		0x49, 0x89, 0x07, //mov    QWORD PTR [r15],rax
		0x4D, 0x8B, 0x57, 0x28, //mov    r10,QWORD PTR [r15+0x28]
		0x4C, 0x89, 0x54, 0x24, 0x20, //mov    QWORD PTR [rsp+0x20],r10
		0x49, 0x8B, 0x47, 0x20, //mov    rax,QWORD PTR [r15+0x20]
		0x4C, 0x89, 0x10, //mov    QWORD PTR [rax],r10
		0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, //mov    rax,0x1
		0x49, 0x89, 0x47, 0x18, //mov    QWORD PTR [r15+0x18],rax
		0x4C, 0x8B, 0x54, 0x24, 0x18, //mov    r10,QWORD PTR [rsp+0x18]
		0x4C, 0x8B, 0x7C, 0x24, 0x10, //mov    r15,QWORD PTR [rsp+0x10]
		0x48, 0x8B, 0x4C, 0x24, 0x08, //mov    rcx,QWORD PTR [rsp+0x8]
		0x48, 0x8B, 0x04, 0x24, //mov    rax,QWORD PTR [rsp]
		0x48, 0x83, 0xC4, 0x28, //add    rsp,0x28
		0xFF, 0x64, 0x24, 0xF8 //jmp    QWORD PTR [rsp-0x8]
	};
	DWORD data_offset = 0x17 + 0x2;
	U64 data_base = AllocateMemory(sizeof(SHELLCODE_DATA), PAGE_READWRITE);
	*(U64*)(remote_call_shellcode.data() + data_offset) = data_base;
	SHELLCODE_DATA data =
	{
		0,
		{ a1 },
		func,
		0,
		freq_called_ptr,
		Read<U64>(freq_called_ptr)
	};
	WriteRaw(rwx_page, remote_call_shellcode.data(), remote_call_shellcode.size());
	Write<SHELLCODE_DATA>(data_base, data);
	uint32_t op = PAGE_NOACCESS;
	if (readonly)
	{
		ProtectMemory(freq_called_ptr, 8, PAGE_READWRITE, &op);
	}
	Write<U64>(freq_called_ptr, rwx_page);
	while (!data.done)
	{
		data = Read<SHELLCODE_DATA>(data_base);
	}
	if (readonly)
	{
		ProtectMemory(freq_called_ptr, 8, op, &op);
	}
	Sleep(100);
	FreeMemory(data_base);
	return data.retn;
}
```



Example of one of my more *nefarious* dlls being injected:

![image](https://user-images.githubusercontent.com/88007716/231946158-f5d826dc-b383-40fe-98e1-80563ef6d7fb.png)


