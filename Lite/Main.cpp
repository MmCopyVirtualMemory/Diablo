//basic
#include <vector>
#include <map>
#include <thread>
#include <iostream>
//required
#include "../../4Est/!Forest/Ida.h"
//driver
#include "../../4Est/!Forest/Driver/Carlos.h"
#define BYPASS CARLOS
#include "../../4Est/!Forest/Driver/Upc.h"
//debug
#include "../../4Est/!Forest/Console.h"

CONSOLE console = CONSOLE();
PROCESS proc = PROCESS();

enum DIABLO_COMMAND : int
{
	CMD_NONE,
	CMD_EXIT,
	CMD_CLS,
	CMD_HELP,
	CMD_ATTACH,
	CMD_INFO,
	CMD_MOD,
	CMD_DUMP,
	CMD_QUERY,
	CMD_INJECT,
};
std::map<std::string, DIABLO_COMMAND> cmd_map = 
{
	{"exit", CMD_EXIT},
	{"cls", CMD_CLS},
	{"help", CMD_HELP},
	{"attach", CMD_ATTACH},
	{"info", CMD_INFO},
	{"mod", CMD_MOD},
	{"dump", CMD_DUMP},
	{"query", CMD_QUERY},
	{"inject", CMD_INJECT},
};
int main() 
{
	SetConsoleTitle(_(L""));
	if (!BYPASS::Init())
	{
		std::cout << _("DRV") << std::endl;
		Sleep(10000);
		return -1;
	}
	while (true) 
	{
		console.Color(CONSOLE::COLOR::COLOR_LIGHT_RED);
		std::cout << _("DIABLO=> ");
		console.Color(CONSOLE::COLOR::COLOR_LIGHT_AQUA);
		std::string input;
		std::getline(std::cin, input);
		std::vector<std::string> cmds;
		std::string split = " ";
		int pos = input.find(split);
		while (pos != std::string::npos)
		{
			cmds.push_back(input.substr(0, pos));
			input.erase(0, pos + 1);
			pos = input.find(split);
		}
		cmds.push_back(input.substr(0));
		switch (cmd_map[cmds[0]])
		{
		case CMD_NONE:
		{
			std::cout << _("COMMAND NOT FOUND") << std::endl;
			break;
		}
		case CMD_EXIT:
		{
			exit(0);
			break;
		}
		case CMD_CLS:
		{
			console.Clear();
			break;
		}
		case CMD_HELP: 
		{
			std::cout << _("attach {process.exe}                  : attaches to the specified process") << std::endl;
			std::cout << _("info                                  : displays process info") << std::endl;
			std::cout << _("mod {module.dll}                      : displays module info") << std::endl;
			std::cout << _("dump {module.dll}                     : dumps the module to disk") << std::endl;
			std::cout << _("query {address}                       : query basic information about the memory provided") << std::endl;
			std::cout << _("pattern {module.dll} {aob} {mask}     : finds all occurances of a pattern in the specified module") << std::endl;
			std::cout << _("inject {method 1->5}                  : injects a dll into the target program") << std::endl;
			break;
		}
		case CMD_ATTACH: 
		{
			std::wstring wide_proc_name = std::wstring(cmds[1].begin(), cmds[1].end());
			if (!!(proc = PROCESS::GetPid(wide_proc_name)))
			{
				std::string buffer = _("ATTACHED TO [");
				buffer += cmds[1];
				buffer += _("]: ");
				buffer += std::to_string(proc.pid);
				SetConsoleTitleA(buffer.c_str());
			}
			else 
			{
				std::cout << _("PROCESS NOT RUNNING") << std::endl;
			}
			break;
		}
		case CMD_INFO:
		{
			std::cout << _("============================================================================") << std::endl;
			for (auto mod : proc.GetModules()) 
			{
				std::cout << mod.dll_name << _(" 0x") << std::hex << mod.base << _(" SIZE: 0x") << mod.size << _(" EP: 0x") << mod.entry << std::dec << std::endl;
			}
			std::cout << _("============================================================================") << std::endl;

			break;
		}
		case CMD_MOD: 
		{
			PROCESS::MODULE mod = proc.GetModule(cmds[1], false);
			std::cout << _("============================================================================") << std::endl;
			std::cout << _("BASE       : 0x") << std::hex << mod.base << std::dec << std::endl;
			std::cout << _("SIZE       : 0x") << std::hex << mod.size << std::dec << std::endl;
			
			for (auto [key, val] : mod.sections)
			{
				std::string page_protection = "";
				if (val.Characteristics & IMAGE_SCN_MEM_READ)
				{
					page_protection += _("R");
				}
				if (val.Characteristics & IMAGE_SCN_MEM_WRITE)
				{
					page_protection += _("W");
				}
				if (val.Characteristics & IMAGE_SCN_MEM_EXECUTE)
				{
					page_protection += _("X");
				}
				std::cout << key << std::hex <<_(" ADDR: 0x") << mod.base + val.VirtualAddress << _(" SIZE: 0x")  << val.SizeOfRawData << _(" INFO: 0x") << val.Characteristics << _(" PAGES: ") << page_protection << std::endl;
			}
			std::cout << _("============================================================================") << std::endl;
			break;
		}
		case CMD_DUMP: 
		{
			proc.DumpModule(cmds[1], cmds[1] + _(".bin"));
			break;
		}
		case CMD_QUERY:
		{
			bool good = true;
			U64 addr = 0;
			try 
			{
				addr = std::stoull(cmds[1], 0, 16);
			}
			catch (std::exception excpt) 
			{
				good = false;
				std::cout << _("INVALID ADDRESS") << std::endl;
			} 
			if (good) 
			{
				MEMORY_BASIC_INFORMATION mbi;
				proc.QueryMemory(addr, mbi);
				std::string page_protection = _("");
				switch (mbi.Protect)
				{
				case PAGE_NOACCESS: 
				{
					page_protection = _("N");
					break;
				}
				case PAGE_READONLY:
				{
					page_protection = _("R");
					break;
				}
				case PAGE_READWRITE:
				{
					page_protection = _("RW");
					break;
				}
				case PAGE_EXECUTE: 
				{
					page_protection = _("X");
				}
				case PAGE_EXECUTE_READ: 
				{
					page_protection = _("RX");
				}
				case PAGE_EXECUTE_READWRITE:
				{
					page_protection = _("RWX");
				}
				}
				std::cout << _("============================================================================") << std::endl;
				std::cout << _("BASE       : 0x") << std::hex << mbi.BaseAddress << std::dec << std::endl;
				std::cout << _("ALLOC BASE : 0x") << std::hex << mbi.AllocationBase << std::dec << std::endl;
				std::cout << _("ALLOC PROT : 0x") << std::hex << mbi.AllocationProtect << std::dec << std::endl;
				std::cout << _("SIZE       : 0x") << std::hex << mbi.RegionSize << std::dec << std::endl;
				std::cout << _("STATE      : 0x") << std::hex << mbi.State << std::dec << std::endl;
				std::cout << _("PROTECT    : 0x") << std::hex << mbi.Protect << _(" ") << page_protection << std::dec << std::endl;
				std::cout << _("TYPE       : 0x") << std::hex << mbi.Type << std::dec << std::endl;
				std::cout << _("============================================================================") << std::endl;
			}
			break;
		}
		case CMD_INJECT: 
		{
			enum class INJECT_TECH : U8
			{
				//ll
				LOAD_LIBRARY = 0,
				//manual map
				RWX_ALLOC = 1,
				PTE_RWNX_SWAP = 2,
				RWX_MEME = 3,
			};
			static std::vector<std::string> allocation_techs =
			{
				_("LOAD LIBRARY"),
				_("RWX ALLOC"),
				_("PTE RWNX SWAP"),
				_("RWX MEME"),
			};
			INJECT_TECH alloc_tech = INJECT_TECH::LOAD_LIBRARY;
			try 
			{
				alloc_tech = (INJECT_TECH)std::stoi(cmds[1]);
			}
			catch (std::exception e) {}
			wchar_t flnm[MAX_PATH];
			flnm[0] = L'\0';
			OPENFILENAMEW file = {};
			file.lStructSize = sizeof(OPENFILENAMEW);
			file.Flags = OFN_FILEMUSTEXIST;
			file.nMaxFile = MAX_PATH;
			file.lpstrFile = flnm;
			if (GetOpenFileNameW(&file))
			{
				std::wstring wide_dll_path = flnm;
				std::string ansi_dll_path = std::string(wide_dll_path.begin(), wide_dll_path.end());
				std::vector<BYTE> dll = {};
				if (ReadFileToMemory(wide_dll_path, &dll))
				{
					if (proc.arch == PROCESS::ARCH::X64) 
					{
						PE image = dll.data();
						if (image.valid) 
						{
							std::cout << _("============================================================================") << std::endl;
							std::cout << ansi_dll_path << std::endl;
							std::cout << allocation_techs[(U8)alloc_tech] << std::endl;
							std::cout << _("[Y/N]: ");
							std::string confirm_inject;
							std::cin >> confirm_inject;
							if (confirm_inject == _("Y"))
							{
								U64 freq_called_ptr = proc.GetModule(_("kernel32.dll"), false).base + 0x81810;// VirtualAlloc
								if (alloc_tech == INJECT_TECH::LOAD_LIBRARY)
								{
									U64 shell_base = proc.AllocateMemory(PAGE_SIZE, PAGE_EXECUTE_READWRITE);
									proc.RemoteCallLoadLibraryA((U64)LoadLibraryA, ansi_dll_path, shell_base, freq_called_ptr, true);
									proc.FreeMemory(shell_base);
								}
								else //manual map with different allocations
								{
									U64 alloc_base = NULL;
									switch (alloc_tech)
									{
									case INJECT_TECH::RWX_ALLOC: //rwx alloc (default)
									{
										alloc_base = proc.AllocateMemory(image.size + PAGE_SIZE + PAGE_SIZE, PAGE_EXECUTE_READWRITE);
										break;
									}
									case INJECT_TECH::PTE_RWNX_SWAP: //pte nx + rw swap todo
									{
										alloc_base = proc.AllocateMemory(image.size + PAGE_SIZE + PAGE_SIZE, PAGE_NOACCESS);
										for (U64 cursor = alloc_base; cursor < alloc_base + image.size + PAGE_SIZE + PAGE_SIZE; cursor += PAGE_SIZE)
										{
											//set all ptes to rwx
										}
										break;
									}
									case INJECT_TECH::RWX_MEME: //rwx signed dll overwrite todo
									{
										break;
									}
									}
									std::cout << _("MAP : 0x") << std::hex << alloc_base << _(" | 0x") << image.size << std::dec << std::endl;
									
									proc.WriteRaw(alloc_base, image.new_image.data()/* + image.header_size*/, image.size/* - image.header_size*/);
									//call entrypoint
									U64 dll_main_shell = alloc_base + image.size;
									U64 remcrt = dll_main_shell + PAGE_SIZE;
									U64 data_base = proc.AllocateMemory(sizeof(PROCESS::MANUAL_MAPPING_DATA), PAGE_READWRITE);
									PROCESS::MANUAL_MAPPING_DATA mmap_data = {}; //thanks cruz
									mmap_data.gpa = (U64)GetProcAddress;
									mmap_data.lla = (U64)LoadLibraryA;
									mmap_data.dllmain = alloc_base + image.entry;
									mmap_data.params.base = alloc_base;
									mmap_data.params.reason = DLL_PROCESS_ATTACH;
									mmap_data.params.reserved = 0;
									proc.Write<PROCESS::MANUAL_MAPPING_DATA>(data_base, mmap_data);
									proc.WriteRaw(dll_main_shell, PROCESS::DllMainShellcode, PAGE_SIZE);
									proc.RemoteCallShellcode(dll_main_shell, data_base, remcrt, freq_called_ptr, true);
									if ((alloc_tech == INJECT_TECH::RWX_ALLOC || alloc_tech == INJECT_TECH::PTE_RWNX_SWAP) && alloc_base)
									{
										std::cout << _("FREE MEMORY? [Y/N]: ");
										std::string confirm_free;
										std::cin >> confirm_free;
										if (confirm_free == _("Y"))
										{
											proc.FreeMemory(alloc_base);
										}
									}
								}
								std::cout << _("============================================================================") << std::endl;
							}
							else 
							{
								std::cout << _("USER CANCELLED") << std::endl;
							}
						}
						else 
						{
							std::cout << _("INVALID IMAGE") << std::endl;
						}
					}
					else 
					{
						//32 bit
					}
				}
				else
				{
					std::cout << _("INVALID PATH") << std::endl;
				}
			}
			break;
		}
		}
	}
	Sleep(-1);
}