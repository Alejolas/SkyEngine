#pragma once

#include <iostream>
#include <string>
#include <Windows.h>
#include <TlHelp32.h>

// datatype for a module in memory (dll, regular exe) 
struct module
{
	DWORD_PTR BaseAddress;
	DWORD Size;
};

class Memory
{
public:
	module TargetModule;  // Hold target module
	HANDLE TargetProcess; // for target process
	DWORD  TargetId;      // for target process

	// Opens a handle to a process with the given name.
	// Returns nullptr and prints an error message on failure.
	HANDLE GetProcess(const char* processName)
	{
		WCHAR wProcessName[MAX_PATH] = { 0 };
		mbstowcs(wProcessName, processName, strlen(processName));

		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		if (snapshot == INVALID_HANDLE_VALUE) {
			std::cerr << "Failed to create snapshot: " << GetLastError() << std::endl;
			return nullptr;
		}

		PROCESSENTRY32 entry;
		entry.dwSize = sizeof(entry);

		do {
			if (!_wcsicmp(entry.szExeFile, wProcessName)) {
				TargetId = entry.th32ProcessID;
				CloseHandle(snapshot);

				TargetProcess = OpenProcess(PROCESS_ALL_ACCESS, false, TargetId);
				if (TargetProcess == NULL) {
					std::cerr << "Failed to open process: " << GetLastError() << std::endl;
					return nullptr;
				}

				return TargetProcess;
			}
		} while (Process32Next(snapshot, &entry));

		CloseHandle(snapshot);
		return nullptr;
	}

	// Gets information about the given module in the target process.
	// Returns a module with null pointers and prints an error message on failure.
	module GetModule(const char* moduleName) {
		WCHAR wModuleName[MAX_PATH] = { 0 };
		mbstowcs(wModuleName, moduleName, strlen(moduleName));

		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, TargetId);
		if (snapshot == INVALID_HANDLE_VALUE) {
			std::cerr << "Failed to create snapshot: " << GetLastError() << std::endl;
			module mod = { 0, 0 };
			return mod;
		}

		MODULEENTRY32 mEntry;
		mEntry.dwSize = sizeof(mEntry);

		do {
			if (!_wcsicmp(mEntry.szModule, wModuleName)) {
				CloseHandle(snapshot);

				TargetModule = { (DWORD_PTR)mEntry.hModule, mEntry.modBaseSize };
				return TargetModule;
			}
		} while (Module32Next(snapshot, &mEntry));

		CloseHandle(snapshot);
		module mod = { 0, 0 };
		return mod;
	}

	// Writes a value to a memory address in the target process.
	// Returns true on success, false on failure.
	template <typename T>
	bool WriteMemory(DWORD_PTR address, T value) {
		if (!WriteProcessMemory(TargetProcess, reinterpret_cast<LPVOID>(address), &value, sizeof(T), nullptr)) {
			std::cerr << "Failed to write memory: " << GetLastError() << std::endl;
			return false;
		}
		return true;
	}

	// Reads a value from a memory address in the target process.
	// Returns the read value.
	template <typename T>
	T ReadMemory(DWORD_PTR address) {
		T value;
		if (!ReadProcessMemory(TargetProcess, reinterpret_cast<LPCVOID>(address), &value, sizeof(T), nullptr)) {
			std::cerr << "Failed to read memory: " << GetLastError() << std::endl;
		}
		return value;
	}

	// Compares a region in memory with a pattern and mask.
	// Returns true if the pattern matches the memory region according to the mask.
	bool MemoryCompare(const BYTE* data, const BYTE* pattern, const char* mask) {
		for (; *mask; ++mask, ++data, ++pattern) {
			if (*mask == 'x' && *data != *pattern) {
				return false;
			}
		}
		return (*mask == NULL);
	}

	// Finds a signature in the memory of the target process.
	// Returns the address of the found signature, or NULL if it was not found.
	DWORD_PTR FindSignature(DWORD_PTR start, DWORD size, const char* sig, const char* mask)
	{
		BYTE* data = new BYTE[size];
		SIZE_T bytesRead;

		if (!ReadProcessMemory(TargetProcess, reinterpret_cast<LPVOID>(start), data, size, &bytesRead)) {
			std::cerr << "Failed to read memory: " << GetLastError() << std::endl;
			delete[] data;
			return NULL;
		}

		for (DWORD i = 0; i < size; i++)
		{
			if (MemoryCompare((const BYTE*)(data + i), (const BYTE*)sig, mask)) {
				delete[] data;
				return start + i;
			}
		}
		delete[] data;
		return NULL;
	}
};