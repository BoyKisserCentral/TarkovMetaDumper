#include <cstdio>
#include <windows.h>

#include "metadata.h"
#include "offsets.h"

static FILE* console = nullptr;

static void show_console()
{
    AllocConsole();
    errno_t _ = freopen_s(&console, "CONOUT$", "w", stdout);
    SetConsoleTitleW(L"Tarkov Meta Dumper");
}

static void hide_console()
{
    errno_t _ = fclose(console);
    FreeConsole();
}

void init(HMODULE this_module)
{
    // wait for GameAssembly.dll to be loaded
    while (!GetModuleHandleA("GameAssembly.dll"))
    {
        // let it burn
    }
    
    // load early offsets
    offsets::init_early();

    // hook functions
    metadata::hook_key_function();

    // wait for game to load key
    while (!metadata::request_key) Sleep(1);

    // load late offsets
    offsets::init_late();
    
    // wait for game to decrypt meta
    Sleep(1000);

    // decrypt meta
    metadata::decrypt();
    
    Sleep(5000);
    
    // get rid of our console
    hide_console();
    
    // done
    FreeLibraryAndExitThread(this_module, 0);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        show_console();
        CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(init), hModule, 0, nullptr); // NOLINT(clang-diagnostic-cast-function-type-strict)
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
	
    return TRUE;
}

