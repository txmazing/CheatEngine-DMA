#include "hooks.h"
#include "DMALibrary/Memory/Memory.h"
#include "Memory/memmy.h"
#include "Memory/vad.h"

namespace Hooks
{
	std::vector<c_memory_region<vad_info>> memoryMap;
	std::vector<vad_info> vad_infos;

	HANDLE hk_open_process(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)
	{
		if (mem.Init(dwProcessId))
		{
			PVMMDLL_MAP_VAD vads;
			memoryMap.clear();
			vad_infos.clear();

			if (!VMMDLL_Map_GetVadW(mem.vHandle, mem.current_process.PID, true, &vads))
				return false;

			std::vector<vad_info> vad_infos;
			for (size_t i = 0; i < vads->cMap; i++)
			{
				auto vad = vads->pMap[i];
				vad_infos.push_back(vad_info(vad.wszText, vad.vaStart, vad.vaEnd, vad));
			}

			for (size_t i = 0; i < vad_infos.size(); i++)
			{
				size_t regionSize = vad_infos[i].get_end() - vad_infos[i].get_start() + 1;
				//printf("Region: %s, Start: %llx, End: %llx, Size: %llx\n", vad_infos[i].get_name().c_str(), vad_infos[i].get_start(), vad_infos[i].get_end(), regionSize);
				memoryMap.push_back(c_memory_region<vad_info>(vad_infos[i], vad_infos[i].get_start(), regionSize));
			}
			return (HANDLE)0x69;
		}
		return false;
	}

	BOOL hk_read(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)
	{
		return mem.Read((UINT64)lpBaseAddress, lpBuffer, nSize, (PDWORD)lpNumberOfBytesRead);
	}

	bool hk_write(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)
	{
		return mem.Write((UINT64)lpBaseAddress, lpBuffer, nSize);
	}

	//Memory in VirtualQuery Is always rounded down, getMemoryRegionContaining will find the nearest (rounded down) region that contains the address.
	//or if it's equal return the exact region.
	SIZE_T hk_virtual_query(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)
	{
		MEMORY_BASIC_INFORMATION meminfo;
		uintptr_t address = reinterpret_cast<uintptr_t>(lpAddress);
		auto it = std::lower_bound(memoryMap.begin(), memoryMap.end(), address,
		                           [](const c_memory_region<vad_info>& region, uintptr_t addr)
		                           {
			                           return region.get_region_start() <= addr;
		                           });

		if (it == memoryMap.end())
		{
			return 0;
		}
		//printf("[%llx] Found region: %llx - %llx\n", address, it->get_region_start(), it->get_region_end());
		if (it->get_region_size() > 0)
		{
			//We have Protection hardcoded rn, because we're DMA and we can read all pages. uncomment the line in get_protection & comment the PAGE_READWRITE to use the real protection that the page has.
			auto found_vad = it->get_object();
			auto rangeStart = it->get_region_start();
			auto rangeEnd = it->get_region_end();
			auto size = rangeEnd - rangeStart + 1;
			meminfo.BaseAddress = reinterpret_cast<PVOID>(rangeStart);
			meminfo.AllocationBase = reinterpret_cast<PVOID>(rangeStart);
			meminfo.AllocationProtect = found_vad.get_protection();
			meminfo.RegionSize = size;
			meminfo.State = found_vad.get_state();
			meminfo.Protect = found_vad.get_protection();
			meminfo.Type = found_vad.get_type();
			meminfo.PartitionId = 0;
			memcpy(lpBuffer, &meminfo, sizeof(meminfo));
			return sizeof(meminfo);
		}

		return 0;
	}
}
