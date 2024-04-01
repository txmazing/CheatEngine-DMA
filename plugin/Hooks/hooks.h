#pragma once
#include "CheatEngine/cepluginsdk.h"
#include <TlHelp32.h>

namespace Hooks
{
	//Mem.cpp
	extern SIZE_T hk_virtual_query(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
	extern bool hk_write(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead);
	extern BOOL hk_read(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead);
	extern HANDLE hk_open_process(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);

	//Process.cpp
	extern HANDLE hk_create_tool_help_32_snapshot(DWORD dwFlags, DWORD th32ProcessID);
	extern BOOL hk_process_32_first(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
	extern BOOL hk_process_32_next(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);

	//Modules.cpp
	extern BOOL hk_module_32_next(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
	extern BOOL hk_module_32_first(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
}
