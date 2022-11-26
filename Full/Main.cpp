#include "../../4/!FourCore/Draw/ImOverlay.h"
#include "../../4/!FourCore/Controller/Upc.h"
#include "../../4/!FourCore/Driver/Declan.h"
#include "../../4/!FourCore/Utility/Console.h"
using BYPASS = DECLAN;
UPC* proc = new UPC
(
    BYPASS::GetProcessBaseAddress, //base
    BYPASS::GetPeb, //peb
    BYPASS::ReadRaw, //read
    BYPASS::WriteRaw, //write
    BYPASS::FreeMemory, //free
    BYPASS::AllocateMemory, //alloc
    BYPASS::ProtectMemory,//protect
    BYPASS::QueryMemory
);
static IM_OVERLAY* canvas = new IM_OVERLAY();
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg)
    {
    case WM_SIZE:
        if (canvas->g_pd3dDevice != NULL && wParam != SIZE_MINIMIZED)
        {
            canvas->g_d3dpp.BackBufferWidth = LOWORD(lParam);
            canvas->g_d3dpp.BackBufferHeight = HIWORD(lParam);
            canvas->ResetDevice();
        }
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU) // Disable ALT application menu
            return 0;
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}
namespace diablo
{
    char process_name[MAX_PATH];
    namespace process 
    {
        std::map<std::string, UTIL::MODULE> module_map = {};
        std::vector<uint64_t> veh = {};
    }
    namespace debug
    {
        bool console = false;
        bool log = false;
    }
    namespace window 
    {
        float width = 1280;
        float height = 800;
    }
}



int main() 
{
    if (!BYPASS::Init())
    {
        std::cout << _("DRV") << std::endl;
        Sleep(10000);
        return -1;
    }
	canvas->onDraw = []() 
	{
        ImGui::StyleColorsDark();
        ImGuiWindowFlags flags = ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoMove;
        ImGui::SetNextWindowPos({ 0, 0 });
        ImGui::SetNextWindowSize({ diablo::window::width, diablo::window::height });
        if (ImGui::Begin(_("DIABLO"), 0, flags))
		{
            if (ImGui::BeginTabBar(_("TABS")))
            {
                if (ImGui::BeginTabItem(_("PROCESS")))
                {
                    ImGui::InputText(_("##PROCESS_NAME"), diablo::process_name, sizeof(diablo::process_name));
                    ImGui::SameLine();
                    if (ImGui::Button(_("ATTACH")))
                    {
                        std::string ansi_proc_name = std::string(diablo::process_name);
                        std::wstring wide_proc_name = std::wstring(ansi_proc_name.begin(), ansi_proc_name.end());
                        if (proc->Attach(wide_proc_name))
                        {
                            //process running
                            //std::cout << _("SUCCESS!!!") << std::endl;
                        }
                        else
                        {
                            //process not running
                        }
                    }
                    ImGui::EndTabItem();
                }
                if (ImGui::BeginTabItem(_("VEH")))
                {
                    if (ImGui::Button(_("UPDATE")))
                    {
                        diablo::process::veh = proc->GetVeh();
                    }
                    for (uint64_t handler : diablo::process::veh)
                    {
                        std::pair<std::string, UTIL::MODULE> mod = {};
                        if (UTIL::WithinModule(handler, diablo::process::module_map, mod))
                        {
                            ImGui::Text(_("%s + 0x%x"), mod.first.c_str(), handler - mod.second.base);
                        }
                        else 
                        {
                            ImGui::Text(_("0x%p"), handler);
                            //floating in heap or somewhere else
                            //hidden module finder ??
                            //nah im a lzy btch
                        }
                    }
                    ImGui::EndTabItem();
                }
                if (ImGui::BeginTabItem(_("MODULES")))
                {
                    if (ImGui::Button(_("UPDATE")))
                    {
                        std::map<std::string, UTIL::MODULE> temp_module_map = {};
                        proc->LoopModules(
                            [&](NT::LDR_DATA_TABLE_ENTRY64 current_module)
                            {
                                wchar_t dll_name[MAX_PATH];
                                proc->ReadRaw((uint64_t)current_module.BaseDllName.Buffer, &dll_name, sizeof(dll_name));
                                std::wstring wide_mod_name = dll_name;
                                std::string ansi_mod_name = std::string(wide_mod_name.begin(), wide_mod_name.end());
                                UTIL::MODULE mod;
                                mod.base = current_module.DllBase;
                                mod.size = current_module.SizeOfImage;
                                mod.entry = current_module.EntryPoint;
                                if (mod.base && mod.size)
                                {
                                    proc->ReadRaw(mod.base, &mod.dos, sizeof(IMAGE_DOS_HEADER));
                                    proc->ReadRaw(mod.base + mod.dos.e_lfanew, &mod.nt, sizeof(IMAGE_NT_HEADERS));
                                    uint64_t first_section = (uint64_t)IMAGE_FIRST_SECTION(&mod.nt) - (uint64_t)&mod.nt + mod.base + mod.dos.e_lfanew;
                                    for (int i = 0; i < mod.nt.FileHeader.NumberOfSections; i++)
                                    {
                                        IMAGE_SECTION_HEADER scn = proc->Read<IMAGE_SECTION_HEADER>(first_section + (i * sizeof(IMAGE_SECTION_HEADER)));
                                        mod.sections[(char*)scn.Name] = scn;
                                        uint64_t start = scn.VirtualAddress;
                                        uint64_t end = scn.VirtualAddress + scn.SizeOfRawData;
                                        uint32_t size = scn.SizeOfRawData;
                                    }
                                }
                                temp_module_map[ansi_mod_name] = mod;
                            }
                        );
                        diablo::process::module_map = temp_module_map;
                    }
                    for (std::pair<std::string, UTIL::MODULE> current_module : diablo::process::module_map)
                    {
                        std::string module_name = current_module.first;
                        UTIL::MODULE module_data = current_module.second;
                        if (ImGui::CollapsingHeader(module_name.c_str()))
                        {
                            ImGui::Text(_("BASE: 0x%p"), module_data.base);
                            ImGui::Text(_("SIZE: 0x%x"), module_data.size);
                            for (std::pair<std::string, IMAGE_SECTION_HEADER> current_section : module_data.sections)
                            {
                                std::string section_name = current_section.first;
                                IMAGE_SECTION_HEADER section_data = current_section.second;

                                std::string page_protection = "";
                                if (section_data.Characteristics & IMAGE_SCN_MEM_READ)
                                {
                                    page_protection += _("R");
                                }
                                if (section_data.Characteristics & IMAGE_SCN_MEM_WRITE)
                                {
                                    page_protection += _("W");
                                }
                                if (section_data.Characteristics & IMAGE_SCN_MEM_EXECUTE)
                                {
                                    page_protection += _("X");
                                }
                                ImGui::Text(section_name.c_str());
                                ImGui::Text(_("  -> 0x%p"), module_data.base + section_data.VirtualAddress);
                                ImGui::Text(_("  -> 0x%x"), section_data.SizeOfRawData);
                                ImGui::Text(_("  -> 0x%x"), section_data.Characteristics);
                                ImGui::Text(_("  -> %s"), page_protection);
                            }
                            if (ImGui::Button(_("DUMP")))
                            {
                                proc->DumpModule(std::wstring(module_name.begin(), module_name.end()), module_name + _(".bin"));
                            }
                        }
                    }
                    ImGui::EndTabItem();
                }
                if (ImGui::BeginTabItem(_("SCANNER")))
                {
                    static char start_buffer[256];
                    ImGui::InputText(_("START"), start_buffer, sizeof(start_buffer));
                    std::string start_str = std::string(start_buffer);
                    uint64_t start = 0;
                    bool good_start = true;
                    try
                    {
                        start = std::stoull(start_str, 0, 16);
                    }
                    catch (std::exception e)
                    {
                        good_start = false;
                    }

                    static char end_buffer[256];
                    ImGui::InputText(_("END"), end_buffer, sizeof(end_buffer));
                    std::string end_str = std::string(end_buffer);
                    uint64_t end = 0xffffffffff;
                    bool good_end = true;
                    try
                    {
                        end = std::stoull(end_str, 0, 16);
                    }
                    catch (std::exception e)
                    {
                        good_end = false;
                    }

                    if (ImGui::BeginTabBar(_("DATA")))
                    {
                        if (ImGui::BeginTabItem(_("INT")))
                        {
                            static std::map<uint64_t, int> previous_scan = {};
                            static int search_value = 0;
                            static const char* scan_types[] = { ("<"), ("<="), (">"), (">="), ("=="), ("?"), ("c"), ("u") };
                            static int selected_type = 0;
                            ImGui::Combo(_("OPERATION"), &selected_type, scan_types, IM_ARRAYSIZE(scan_types));
                            UPC::SCAN_TYPE operation = (UPC::SCAN_TYPE)selected_type;
                            ImGui::InputInt(_("VALUE"), &search_value);
                            if (ImGui::Button(_("FIRST")))
                            {
                                previous_scan = proc->FirstScan<int>(search_value, operation/*, start, end*/); /////////////////ADD VARIABLE DISTANCE SCANNING BACK////////////////////////////////////////////////////////////
                            }
                            ImGui::SameLine();
                            if (ImGui::Button(_("NEXT")))
                            {
                                previous_scan = proc->NextScan<int>(search_value, operation, previous_scan);
                            }
                            ImGui::Text(_("HITS: %i"), previous_scan.size());
                            for (std::pair<uint64_t, int> scan_result : previous_scan)
                            {
                                ImGui::Text(_("0x%p, 0x%x"), scan_result.first, scan_result.second);
                            }
                            ImGui::EndTabItem();
                        }
                        if (ImGui::BeginTabItem(_("FLOAT")))
                        {
                            static std::map<uint64_t, float> previous_scan = {};
                            static float search_value = 0;
                            static const char* scan_types[] = { ("<"), ("<="), (">"), (">="), ("=="), ("?"), ("c"), ("u") };
                            static int selected_type = 0;
                            ImGui::Combo(_("OPERATION"), &selected_type, scan_types, IM_ARRAYSIZE(scan_types));
                            UPC::SCAN_TYPE operation = (UPC::SCAN_TYPE)selected_type;
                            ImGui::InputFloat(_("VALUE"), &search_value);
                            if (ImGui::Button(_("FIRST")))
                            {
                                previous_scan = proc->FirstScan<float>(search_value, operation, start, end);
                            }
                            ImGui::SameLine();
                            if (ImGui::Button(_("NEXT")))
                            {
                                previous_scan = proc->NextScan<float>(search_value, operation, previous_scan);
                            }
                            for (std::pair<uint64_t, int> scan_result : previous_scan)
                            {
                                ImGui::Text(_("0x%p, %f"), scan_result.first, scan_result.second);
                            }
                            ImGui::EndTabItem();
                        }
                        if (ImGui::BeginTabItem(_("DOUBLE")))
                        {
                            static std::map<uint64_t, double> previous_scan = {};
                            static double search_value = 0;
                            static const char* scan_types[] = { ("<"), ("<="), (">"), (">="), ("=="), ("?"), ("c"), ("u")};
                            static int selected_type = 0;
                            ImGui::Combo(_("OPERATION"), &selected_type, scan_types, IM_ARRAYSIZE(scan_types));
                            UPC::SCAN_TYPE operation = (UPC::SCAN_TYPE)selected_type;
                            ImGui::InputDouble(_("VALUE"), &search_value);
                            if (ImGui::Button(_("FIRST")))
                            {
                                previous_scan = proc->FirstScan<double>(search_value, operation, start, end);
                            }
                            ImGui::SameLine();
                            if (ImGui::Button(_("NEXT")))
                            {
                                previous_scan = proc->NextScan<double>(search_value, operation, previous_scan);
                            }
                            for (std::pair<uint64_t, int> scan_result : previous_scan)
                            {
                                ImGui::Text(_("0x%p, %d"), scan_result.first, scan_result.second);
                            }
                            ImGui::EndTabItem();
                        }
                        if (ImGui::BeginTabItem(_("PATTERN")))
                        {
                            //TODO:
                            //ImGui::InputScalar("input u64", ImGuiDataType_U64, &u64_v, inputs_step ? &u64_one : NULL);
                            static char pattern_buffer[256];
                            ImGui::InputText(_("PATTERN"), pattern_buffer, sizeof(pattern_buffer));
                            std::string pattern = std::string(pattern_buffer);
                            static char mask_buffer[256];
                            ImGui::InputText(_("MASK"), mask_buffer, sizeof(mask_buffer));
                            std::string mask = std::string(mask_buffer);
                            static char base_buffer[256];
                            ImGui::InputText(_("BASE"), base_buffer, sizeof(base_buffer));
                            std::string base_str = std::string(base_buffer);
                            uint64_t base = 0;
                            bool good_base = true;
                            try
                            {
                                base = std::stoull(base_str, 0, 16);
                            }
                            catch (std::exception e)
                            {
                                good_base = false;
                            }
                            static char size_buffer[256];
                            ImGui::InputText(_("SIZE"), size_buffer, sizeof(size_buffer));
                            std::string size_str = std::string(size_buffer);
                            uint64_t size = 0;
                            bool good_size = true;
                            try
                            {
                                size = std::stoull(size_str, 0, 16);
                            }
                            catch (std::exception e)
                            {
                                good_size = false;
                            }
                            static std::vector<uint64_t> results = {};
                            if (ImGui::Button(_("UPDATE")))
                            {
                                if (good_base && good_size)
                                {
                                    results = proc->FindPattern(base, size, pattern, mask);
                                }
                            }
                            for (uint64_t result : results)
                            {
                                ImGui::Text(_(" -> %p"), result);
                            }
                            ImGui::EndTabItem();
                        }
                        if (ImGui::BeginTabItem(_("POINTER")))
                        {
                            //get user input for this
                            /*uint64_t addr = 0xdeadbeef;
                            int level = 1;
                            std::map<uint64_t, uint64_t> results = proc->FirstScan<uint64_t>(addr, '==');*/

                            ImGui::EndTabItem();
                        }
                        ImGui::EndTabBar();
                    }
                    ImGui::EndTabItem();
                }
                if (ImGui::BeginTabItem(_("VIEWER")))
                {
                    static char base_buffer[256];
                    ImGui::InputText(_("BASE"), base_buffer, sizeof(base_buffer));
                    std::string base_str = std::string(base_buffer);
                    uint64_t base = 0;
                    bool good_base = true;
                    try
                    {
                        base = std::stoull(base_str, 0, 16);
                    }
                    catch (std::exception e)
                    {
                        good_base = false;
                    }
                    static char size_buffer[256];
                    ImGui::InputText(_("SIZE"), size_buffer, sizeof(size_buffer));
                    std::string size_str = std::string(size_buffer);
                    uint64_t size = 0;
                    bool good_size = true;
                    try
                    {
                        size = std::stoull(size_str, 0, 16);
                    }
                    catch (std::exception e)
                    {
                        good_size = false;
                    }
                    static std::vector<BYTE> memory_block = {};
                    if (ImGui::Button(_("UPDATE")))
                    {
                        if (good_base && good_size)
                        {
                            memory_block.resize(size);
                            proc->ReadRaw(base, memory_block.data(), memory_block.size());
                        }
                    }
                    ImGui::EndTabItem();
                }
                if (ImGui::BeginTabItem(_("DEBUG")))
                {

                    ImGui::EndTabItem();
                }
                ImGui::EndTabBar();
            }
            ImGui::End();
		}
        /*bool fax = true;
        ImGui::ShowDemoWindow(&fax);*/
	};

    std::wstring window_name = _(L"DIABLO_WINDOW");
    std::wstring window_class_name = _(L"DIABLO_WINDOW_CLASS");
	WNDCLASSEXW wc = 
    { 
        sizeof(wc), 
        CS_CLASSDC,
        WndProc, 
        0L, 
        0L, 
        GetModuleHandle(NULL), 
        NULL, 
        NULL, 
        NULL, 
        NULL, 
        window_class_name.c_str(), 
        NULL
    };
	RegisterClassExW(&wc);
	HWND hwnd = CreateWindowW(window_class_name.c_str(), window_name.c_str(), WS_OVERLAPPEDWINDOW, 100, 100, diablo::window::width, diablo::window::height, NULL, NULL, wc.hInstance, NULL);
    ShowWindow(hwnd, SW_SHOWDEFAULT);
    UpdateWindow(hwnd);
	canvas->Run(hwnd);
}