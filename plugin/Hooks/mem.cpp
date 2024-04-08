#include <list>
#include <map>

#include "hooks.h"
#include "DMALibrary/Memory/Memory.h"
#include "Memory/memmy.h"
#include "Memory/vad.h"

namespace Hooks
{
	HANDLE hk_open_process(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)
	{
		if (mem.Init(dwProcessId))
			return (HANDLE)0x69;

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

	std::list<c_memory_region<vad_info>> get_memory_region()
	{
		std::list<c_memory_region<vad_info>> result = { };
		PVMMDLL_MAP_VAD vads = nullptr;

		if (!VMMDLL_Map_GetVadW(mem.vHandle, mem.current_process.PID, true, &vads))
			return { };

		std::vector<vad_info> vad_infos;
		for (size_t i = 0; i < vads->cMap; i++)
		{
			auto vad = vads->pMap[i];
			vad_infos.push_back(vad_info(vad.wszText, vad.vaStart, vad.vaEnd, vad));
		}

		for (size_t i = 0; i < vad_infos.size(); i++)
		{
			size_t regionSize = vad_infos[i].get_end() - vad_infos[i].get_start() + 1;
			result.push_back(c_memory_region<vad_info>(vad_infos[i], vad_infos[i].get_start(), regionSize));
		}
		return result;
	}

	std::map<int, std::pair<uint64_t, std::list<c_memory_region<vad_info>>>> region_cache;

	bool VirtualQueryImpl_(uintptr_t lpAddress, c_memory_region<vad_info>* ret)
	{
		if (region_cache.find(mem.current_process.PID) != region_cache.end())
		{
			auto&& [time, region] = region_cache[mem.current_process.PID];
			if (GetTickCount() - time > 1000)
			{
				auto&& new_region = get_memory_region();
				region_cache.erase(mem.current_process.PID);
				region_cache.insert({mem.current_process.PID, {GetTickCount(), new_region}});
			}
		}
		else
		{
			auto&& new_region = get_memory_region();
			region_cache.insert({mem.current_process.PID, std::pair(GetTickCount(), new_region)});
		}
		auto regions = region_cache[mem.current_process.PID].second;

		auto it = std::lower_bound(regions.begin(), regions.end(), lpAddress,
		                           [](const c_memory_region<vad_info>& region, uintptr_t addr)
		                           {
			                           return region.get_region_start() <= addr;
		                           });
		if (it == regions.end())
			return false;
		*ret = *it;
		return true;
	}

	//Memory in VirtualQuery Is always rounded down, getMemoryRegionContaining will find the nearest (rounded down) region that contains the address.
	//or if it's equal return the exact region.
	SIZE_T hk_virtual_query(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)
	{
		MEMORY_BASIC_INFORMATION meminfo = { };
		c_memory_region<vad_info> info;
		if (!Hooks::VirtualQueryImpl_(reinterpret_cast<uintptr_t>(lpAddress), &info))
			return 0;

		ZeroMemory(&meminfo, sizeof(meminfo));
		auto found_vad = info.get_object();
		auto rangeStart = info.get_region_start();
		auto rangeEnd = info.get_region_end();
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
}
