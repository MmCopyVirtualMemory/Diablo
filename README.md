# Diablo
Reverse engineering program using a driver for memory operations. 

**As of now I haven't decided to post the library that I use for process handling so I will leave that up to the reader to add themselves.**

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


