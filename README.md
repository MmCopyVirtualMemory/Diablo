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
- Module Base
- Module Size
- All Sections [Name, Start Address, Size, Info and Page Protection]
![image](https://user-images.githubusercontent.com/88007716/231944628-b932f2c8-ee89-40e0-951e-8cbb9438678c.png)

## Dump Module
Use the command "dump" followed by the module name you wish to dump. This will dump the module to the same directory as the executable.
## Query Memory
## Inject DLL


