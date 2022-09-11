#include "../../4/!FourCore/Controller/Upc.h"
#include "../../4/!FourCore/Driver/Carlos.h"
#include "../../4/!FourCore/Utility/Console.h"
#include <iostream>
CONSOLE* console = new CONSOLE();

using BYPASS = CARLOS;
UPC* proc = new UPC
(
	UPC::x64,
	BYPASS::GetProcessBaseAddress, //base
	BYPASS::GetPeb, //peb
	BYPASS::ReadRaw, //read
	BYPASS::WriteRaw, //write
	BYPASS::FreeMemory, //free
	BYPASS::AllocateMemory, //alloc
	BYPASS::ProtectMemory,//protect
	BYPASS::QueryMemory
);



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
	CMD_READ,
	CMD_WRITE,
	CMD_QUERY,
	CMD_PATTERN,
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
	{"read", CMD_READ},
	{"write", CMD_WRITE},
	{"query", CMD_QUERY},
	{"pattern", CMD_PATTERN},
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
		console->Color(COLOR_LIGHT_RED);
		std::cout << _("DIABLO=> ");
		console->Color(COLOR_LIGHT_AQUA);
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
			console->Clear();
			break;
		}
		case CMD_HELP: 
		{
			std::cout << _("attach {process.exe}                  : attaches to the specified process") << std::endl;
			std::cout << _("info                                  : displays process info") << std::endl;
			std::cout << _("mod {module.dll}                      : displays module info") << std::endl;
			std::cout << _("dump {module.dll} {dump_name}         : dumps the module to disk") << std::endl;
			std::cout << _("read                                  : ") << std::endl;
			std::cout << _("write                                 : ") << std::endl;
			std::cout << _("query {address}                       : query basic information about the memory provided") << std::endl;
			std::cout << _("pattern {module.dll} {aob} {mask}     : finds all occurances of a pattern in the specified module") << std::endl;
			break;
		}
		case CMD_ATTACH: 
		{
			std::wstring wide_proc_name = std::wstring(cmds[1].begin(), cmds[1].end());
			if (proc->Attach(wide_proc_name))
			{
				std::string buffer = _("ATTACHED TO [");
				buffer += cmds[1];
				buffer += _("]: ");
				buffer += std::to_string(proc->pid);
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
			proc->LoopModules(
				[&](NT::LDR_DATA_TABLE_ENTRY64 current_module)
				{
					wchar_t dll_name[100];
					proc->ReadRaw((uint64_t)current_module.BaseDllName.Buffer, &dll_name, sizeof(dll_name));

					std::wstring wide_mod_name = dll_name;
					std::string asci_mod_name = std::string(wide_mod_name.begin(), wide_mod_name.end());
					std::cout << asci_mod_name << _(" 0x") << std::hex << current_module.DllBase << _(" SIZE: 0x") << current_module.SizeOfImage << _(" EP: 0x") << current_module.EntryPoint << std::dec << std::endl;
				});
			std::cout << _("============================================================================") << std::endl;

			break;
		}
		case CMD_MOD: 
		{
			std::wstring wide_mod_name = std::wstring(cmds[1].begin(), cmds[1].end());
			UPC::MODULE mod = proc->GetModuleInfo(wide_mod_name);
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
			std::wstring wide_mod_name = std::wstring(cmds[1].begin(), cmds[1].end());
			proc->DumpModule(wide_mod_name, cmds[2]);
			break;
		}
		case CMD_READ: 
		{
			break;
		}
		case CMD_WRITE:
		{
			break;
		}
		case CMD_QUERY:
		{
			bool good = true;
			uint64_t addr = 0;
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
				proc->QueryMemory(addr, mbi);
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
		case CMD_PATTERN: 
		{
			std::wstring wide_mod_name = std::wstring(cmds[1].begin(), cmds[1].end());
			UPC::MODULE mod = proc->GetModuleInfo(wide_mod_name);
			std::vector<BYTE*> results = proc->FindPattern(mod.base, mod.size, cmds[2], cmds[3]);
			for (BYTE* result : results)
			{
				std::cout << _("FOUND AT: 0x") << (uint64_t)result << std::endl;
			}
			break;
		}
		}
	}
	Sleep(-1);
}