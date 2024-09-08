#pragma once
#include "../pch.h"
#include "InputManager.h"
#include "Registry.h"
#include "Shellcode.h"
#include "../nt/structs.h"

class Memory
{
private:
    struct LibModules
    {
        HMODULE VMM = nullptr;
        HMODULE FTD3XX = nullptr;
        HMODULE LEECHCORE = nullptr;
    };

    static inline LibModules modules{ };

    struct CurrentProcessInformation
    {
        int PID = 0;
        size_t base_address = 0;
        size_t base_size = 0;
        std::string process_name = "";
    };

    static inline BOOLEAN DMA_INITIALIZED = FALSE;
    static inline BOOLEAN PROCESS_INITIALIZED = FALSE;

    bool DumpMemoryMap(bool debug = false);
    bool SetFPGA();

    std::shared_ptr<c_keys> key;
    c_registry registry;
    c_shellcode shellcode;

public:
    static inline CurrentProcessInformation current_process{ };

    Memory();
    ~Memory();

    c_registry GetRegistry() { return registry; }
    c_keys* GetKeyboard() { return key.get(); }
    c_shellcode GetShellcode() { return shellcode; }

    bool Init(std::string process_name, bool memMap = true, bool debug = false);
    bool Init(int process_pid, bool memMap = true, bool debug = false);

    DWORD GetPidFromName(std::string process_name);
    std::vector<int> GetPidListFromName(std::string process_name);
    std::vector<std::string> GetModuleList(std::string process_name);
    VMMDLL_PROCESS_INFORMATION GetProcessInformation();
    PEB GetProcessPeb();
    size_t GetBaseDaddy(std::string module_name);
    size_t GetBaseSize(std::string module_name);
    uintptr_t GetExportTableAddress(std::string import, std::string process, std::string module, bool kernel = false);
    uintptr_t GetImportTableAddress(std::string import, std::string process, std::string module);
    bool FixCr3();
    bool DumpMemory(uintptr_t address, const std::string& path);

    uint64_t FindSignature(const char* signature, uint64_t range_start, uint64_t range_end, int PID = 0);

    bool Write(uintptr_t address, void* buffer, size_t size) const;
    bool Write(uintptr_t address, void* buffer, size_t size, int pid) const;

    template <typename T>
    void Write(void* address, T value)
    {
        Write(reinterpret_cast<uintptr_t>(address), &value, sizeof(T));
    }

    template <typename T>
    void Write(uintptr_t address, T value)
    {
        Write(address, &value, sizeof(T));
    }

    template <typename T>
    void Write2(uintptr_t address, T value, int pid)
    {
        Write(address, &value, sizeof(T), pid);
    }

    bool Read(uintptr_t address, void* buffer, size_t size) const;
    bool Read(uintptr_t address, void* buffer, size_t size, int pid) const;
    bool Read(uintptr_t address, void* buffer, size_t size, PDWORD read) const;

    template <typename T>
    T Read(void* address)
    {
        T buffer{ };
        Read(reinterpret_cast<uint64_t>(address), &buffer, sizeof(T));
        return buffer;
    }

    template <typename T>
    T Read(uint64_t address)
    {
        return Read<T>(reinterpret_cast<void*>(address));
    }

    template <typename T>
    T Read(void* address, int pid)
    {
        T buffer{ };
        Read(reinterpret_cast<uint64_t>(address), &buffer, sizeof(T), pid);
        return buffer;
    }

    template <typename T>
    T Read(uint64_t address, int pid)
    {
        return Read<T>(reinterpret_cast<void*>(address), pid);
    }

    uint64_t ReadChain(uint64_t base, const std::vector<uint64_t>& offsets);

    VMMDLL_SCATTER_HANDLE CreateScatterHandle() const;
    VMMDLL_SCATTER_HANDLE CreateScatterHandle(int pid) const;
    void CloseScatterHandle(VMMDLL_SCATTER_HANDLE handle);
    void AddScatterReadRequest(VMMDLL_SCATTER_HANDLE handle, uint64_t address, void* buffer, size_t size);
    void AddScatterWriteRequest(VMMDLL_SCATTER_HANDLE handle, uint64_t address, void* buffer, size_t size);
    void ExecuteReadScatter(VMMDLL_SCATTER_HANDLE handle, int pid = 0);
    void ExecuteWriteScatter(VMMDLL_SCATTER_HANDLE handle, int pid = 0);

    VMM_HANDLE vHandle;
};

inline Memory mem;