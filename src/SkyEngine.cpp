#include <iostream>
#include <string>
#include <Windows.h>
#include "Memory.h"

const char* PROCESS_NAME = "felsong-64.exe";

void HandleProcess(Memory& memory) {
	auto mod = memory.GetModule(PROCESS_NAME);
	if (mod.Size != 0) {
		printf("Successfully got module: %s. Base Address: 0x%llX\n", PROCESS_NAME, mod.BaseAddress);

		auto address = memory.FindSignature(mod.BaseAddress, mod.Size, "\x4C\x8B\x0D\x00\x00\x00\x00\x45\x33\xC0\x48\x8B\xCE", "xxx????xxxxxx");
		printf("Signature Address: 0x%llX\n", address);

		auto TaintedAddress = address + memory.ReadMemory<DWORD>(address + 0x3) + 0x7;
		printf("Lua_TaintedPtrOffset : 0x%llX\n", TaintedAddress - mod.BaseAddress);

		printf("Lua is now unlocked...\n");

		while (true)
		{
			memory.WriteMemory<DWORD_PTR>(TaintedAddress, 0);

			// Press 'End' key to break the loop
			if (GetAsyncKeyState(VK_END) & 1)
				break;

			Sleep(1);
		}
	}
	else {
		printf("Failed to get module: %s\n", PROCESS_NAME);
	}
}

int main()
{
	SetConsoleTitle(L"SkyEngine");
	printf("Developed by - WiNiFiX#0204 (Jul 2019) - Modified by Alejolas (May 2023)\n");

	Memory memory;
	HANDLE processHandle = memory.GetProcess(PROCESS_NAME);

	if (processHandle != nullptr) {
		printf("Successfully hooked into process: %s with ID: %i\n", PROCESS_NAME, memory.TargetId);
		HandleProcess(memory);
	}
	else {
		printf("Failed to hook into process: %s. Please launch it then re-open this unlocker.\n", PROCESS_NAME);
	}

	for (auto c = 5; c > 0; c--) {
		printf("Closing in %i\n", c);
		Sleep(1000);
	}
}
