// UE4SS-HVFix: replacement dwmapi.dll proxy for UE4SS.
//
// The stock UE4SS dwmapi.dll proxy just loads ue4ss\UE4SS.dll. On this setup (game launched
// through a hypervisor/driver based loader) UE4SS dies with:
//     "Fatal Error: Was unable to enumerate game modules. Error: [0x6] The handle is invalid."
// because K32EnumProcessModules / K32GetModuleInformation fail for the current process.
//
// This proxy loads the unmodified UE4SS.dll and patches *UE4SS.dll's own import table* so that
// those psapi calls fall back to an in-process implementation (PEB loader list + VirtualQuery
// scan + PE headers) when the original call fails. Nothing in the game or in UE4SS.dll on disk
// is modified. All dwmapi exports are forwarded to C:\Windows\System32\dwmapi.dll.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <intrin.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <wchar.h>

#include "exports.h"

// ---------------------------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------------------------
static wchar_t g_log_path[MAX_PATH * 2] = {};
static CRITICAL_SECTION g_log_cs;
static CRITICAL_SECTION g_enum_cs;
static volatile LONG g_fallback_enum_calls = 0;
static volatile LONG g_fallback_info_calls = 0;
static volatile LONG g_fallback_name_calls = 0;
// Set by env var UE4SS_HVFIX_FORCE=1: skip the original APIs and always use the fallback.
static bool g_force_fallback = false;

static void Log(const char* fmt, ...)
{
    if (!g_log_path[0]) return;
    char buf[2048];
    SYSTEMTIME st;
    GetLocalTime(&st);
    int n = _snprintf_s(buf, sizeof(buf), _TRUNCATE, "[%04u-%02u-%02u %02u:%02u:%02u.%03u][T%05lu] ",
                        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                        GetCurrentThreadId());
    if (n < 0) n = 0;
    va_list ap;
    va_start(ap, fmt);
    int m = _vsnprintf_s(buf + n, sizeof(buf) - n, _TRUNCATE, fmt, ap);
    va_end(ap);
    if (m < 0) m = (int)strlen(buf + n);
    size_t len = n + m;
    if (len + 2 < sizeof(buf)) { buf[len++] = '\r'; buf[len++] = '\n'; }

    EnterCriticalSection(&g_log_cs);
    HANDLE f = CreateFileW(g_log_path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f != INVALID_HANDLE_VALUE)
    {
        DWORD w;
        WriteFile(f, buf, (DWORD)len, &w, nullptr);
        CloseHandle(f);
    }
    LeaveCriticalSection(&g_log_cs);
}

// ---------------------------------------------------------------------------------------------
// Minimal loader structures (x64)
// ---------------------------------------------------------------------------------------------
struct HV_UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWSTR Buffer; };
struct HV_LDR_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;           // 0x00
    LIST_ENTRY InMemoryOrderLinks;         // 0x10
    LIST_ENTRY InInitializationOrderLinks; // 0x20
    PVOID DllBase;                         // 0x30
    PVOID EntryPoint;                      // 0x38
    ULONG SizeOfImage;                     // 0x40
    HV_UNICODE_STRING FullDllName;         // 0x48
    HV_UNICODE_STRING BaseDllName;         // 0x58
};
struct HV_PEB_LDR_DATA
{
    ULONG Length;                          // 0x00
    BOOLEAN Initialized;                   // 0x04
    PVOID SsHandle;                        // 0x08
    LIST_ENTRY InLoadOrderModuleList;      // 0x10
};

static BYTE* PebPtr() { return (BYTE*)__readgsqword(0x60); }
static HMODULE PebImageBase()
{
    __try { return *(HMODULE*)(PebPtr() + 0x10); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

static bool IsReadable(const void* p, SIZE_T size)
{
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(p, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return false;
    return (BYTE*)p + size <= (BYTE*)mbi.BaseAddress + mbi.RegionSize;
}

// Returns NT headers if base looks like a valid mapped PE image.
static IMAGE_NT_HEADERS64* GetNtHeaders(const void* base)
{
    if (!base) return nullptr;
    __try
    {
        if (!IsReadable(base, sizeof(IMAGE_DOS_HEADER))) return nullptr;
        auto dos = (const IMAGE_DOS_HEADER*)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
        if (dos->e_lfanew <= 0 || dos->e_lfanew > 0x1000) return nullptr;
        auto nt = (IMAGE_NT_HEADERS64*)((BYTE*)base + dos->e_lfanew);
        if (!IsReadable(nt, sizeof(IMAGE_NT_HEADERS64))) return nullptr;
        if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
        if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return nullptr;
        return nt;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

// Finds the PEB loader entry for a module base (nullptr if hidden/unlinked).
static HV_LDR_ENTRY* FindLdrEntry(HMODULE base)
{
    __try
    {
        auto ldr = *(HV_PEB_LDR_DATA**)(PebPtr() + 0x18);
        if (!ldr) return nullptr;
        LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
        int guard = 0;
        for (LIST_ENTRY* e = head->Flink; e && e != head && guard < 8192; e = e->Flink, ++guard)
        {
            auto ent = (HV_LDR_ENTRY*)e;
            if (ent->DllBase == base) return ent;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    return nullptr;
}

// ---------------------------------------------------------------------------------------------
// Fallback module enumeration
// ---------------------------------------------------------------------------------------------
static const int kMaxMods = 4096;

static bool AddUnique(HMODULE* list, int& count, HMODULE m)
{
    if (!m || count >= kMaxMods) return false;
    for (int i = 0; i < count; ++i)
        if (list[i] == m) return false;
    list[count++] = m;
    return true;
}

static int CollectModules(HMODULE* list, int* from_peb, int* from_scan)
{
    int count = 0;
    *from_peb = 0;
    *from_scan = 0;

    // 1) Main executable first (EnumProcessModules always returns it first).
    HMODULE exe = PebImageBase();
    if (!exe) exe = GetModuleHandleW(nullptr);
    if (GetNtHeaders(exe)) AddUnique(list, count, exe);

    // 2) PEB loader list (read directly in-process, no NtQueryInformationProcess / ReadProcessMemory).
    __try
    {
        auto ldr = *(HV_PEB_LDR_DATA**)(PebPtr() + 0x18);
        if (ldr)
        {
            LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
            int guard = 0;
            for (LIST_ENTRY* e = head->Flink; e && e != head && guard < 8192; e = e->Flink, ++guard)
            {
                auto ent = (HV_LDR_ENTRY*)e;
                if (GetNtHeaders(ent->DllBase) && AddUnique(list, count, (HMODULE)ent->DllBase)) ++*from_peb;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    // 3) Image mappings not present in the loader list.
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    BYTE* p = (BYTE*)si.lpMinimumApplicationAddress;
    BYTE* end = (BYTE*)si.lpMaximumApplicationAddress;
    MEMORY_BASIC_INFORMATION mbi;
    while (p < end && VirtualQuery(p, &mbi, sizeof(mbi)))
    {
        if (mbi.Type == MEM_IMAGE && mbi.BaseAddress == mbi.AllocationBase && mbi.State == MEM_COMMIT)
        {
            if (GetNtHeaders(mbi.BaseAddress) && AddUnique(list, count, (HMODULE)mbi.BaseAddress)) ++*from_scan;
        }
        BYTE* next = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if (next <= p) break;
        p = next;
    }
    return count;
}

static bool IsCurrentProcess(HANDLE h)
{
    if (h == GetCurrentProcess()) return true;
    DWORD pid = GetProcessId(h);
    return pid != 0 && pid == GetCurrentProcessId();
}

// Base name of a module as UTF-16 (PEB entry, GetModuleFileNameW, or mapped file name).
static bool GetModuleBaseNameFallbackW(HMODULE m, wchar_t* out, DWORD cch)
{
    if (!cch) return false;
    out[0] = 0;
    if (!m) m = PebImageBase();

    if (HV_LDR_ENTRY* ent = FindLdrEntry(m))
    {
        __try
        {
            if (ent->BaseDllName.Buffer && ent->BaseDllName.Length)
            {
                DWORD n = ent->BaseDllName.Length / sizeof(wchar_t);
                if (n >= cch) n = cch - 1;
                memcpy(out, ent->BaseDllName.Buffer, n * sizeof(wchar_t));
                out[n] = 0;
                return true;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    wchar_t path[MAX_PATH * 2];
    DWORD n = GetModuleFileNameW(m, path, ARRAYSIZE(path));
    if (!n) n = GetMappedFileNameW(GetCurrentProcess(), m, path, ARRAYSIZE(path));
    if (!n) return false;
    const wchar_t* s = wcsrchr(path, L'\\');
    s = s ? s + 1 : path;
    wcsncpy_s(out, cch, s, _TRUNCATE);
    return true;
}

// ---------------------------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------------------------
using EnumProcessModules_t = BOOL(WINAPI*)(HANDLE, HMODULE*, DWORD, LPDWORD);
using EnumProcessModulesEx_t = BOOL(WINAPI*)(HANDLE, HMODULE*, DWORD, LPDWORD, DWORD);
using GetModuleInformation_t = BOOL(WINAPI*)(HANDLE, HMODULE, LPMODULEINFO, DWORD);
using GetModuleBaseNameA_t = DWORD(WINAPI*)(HANDLE, HMODULE, LPSTR, DWORD);
using GetModuleBaseNameW_t = DWORD(WINAPI*)(HANDLE, HMODULE, LPWSTR, DWORD);
using GetModuleFileNameExA_t = DWORD(WINAPI*)(HANDLE, HMODULE, LPSTR, DWORD);
using GetModuleFileNameExW_t = DWORD(WINAPI*)(HANDLE, HMODULE, LPWSTR, DWORD);

static EnumProcessModules_t o_EnumProcessModules = nullptr;
static EnumProcessModulesEx_t o_EnumProcessModulesEx = nullptr;
static GetModuleInformation_t o_GetModuleInformation = nullptr;
static GetModuleBaseNameA_t o_GetModuleBaseNameA = nullptr;
static GetModuleBaseNameW_t o_GetModuleBaseNameW = nullptr;
static GetModuleFileNameExA_t o_GetModuleFileNameExA = nullptr;
static GetModuleFileNameExW_t o_GetModuleFileNameExW = nullptr;

static BOOL FallbackEnum(HMODULE* mods, DWORD cb, LPDWORD needed, DWORD orig_err)
{
    static HMODULE list[kMaxMods];
    CRITICAL_SECTION* cs = &g_enum_cs;

    EnterCriticalSection(cs);
    int peb = 0, scan = 0;
    int count = CollectModules(list, &peb, &scan);
    LONG call = InterlockedIncrement(&g_fallback_enum_calls);
    if (call <= 3)
    {
        Log("EnumProcessModules failed (err=%lu) -> fallback #%ld: %d modules (exe + %d from PEB + %d from VirtualQuery scan)",
            orig_err, call, count, peb, scan);
        for (int i = 0; i < count && call == 1; ++i)
        {
            wchar_t name[MAX_PATH] = L"?";
            GetModuleBaseNameFallbackW(list[i], name, ARRAYSIZE(name));
            auto nt = GetNtHeaders(list[i]);
            Log("    [%3d] %p size=0x%08lX %ls", i, list[i], nt ? nt->OptionalHeader.SizeOfImage : 0, name);
        }
    }
    if (count == 0)
    {
        LeaveCriticalSection(cs);
        SetLastError(orig_err);
        return FALSE;
    }
    DWORD bytes = (DWORD)(count * sizeof(HMODULE));
    __try
    {
        if (needed) *needed = bytes;
        if (mods && cb) memcpy(mods, list, bytes < cb ? bytes : (cb / sizeof(HMODULE)) * sizeof(HMODULE));
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        LeaveCriticalSection(cs);
        SetLastError(ERROR_NOACCESS);
        return FALSE;
    }
    LeaveCriticalSection(cs);
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

static BOOL WINAPI Hook_EnumProcessModules(HANDLE h, HMODULE* mods, DWORD cb, LPDWORD needed)
{
    if (!g_force_fallback && o_EnumProcessModules && o_EnumProcessModules(h, mods, cb, needed)) return TRUE;
    DWORD err = GetLastError();
    if (!IsCurrentProcess(h)) { SetLastError(err); return FALSE; }
    return FallbackEnum(mods, cb, needed, err);
}

static BOOL WINAPI Hook_EnumProcessModulesEx(HANDLE h, HMODULE* mods, DWORD cb, LPDWORD needed, DWORD filter)
{
    if (!g_force_fallback && o_EnumProcessModulesEx && o_EnumProcessModulesEx(h, mods, cb, needed, filter)) return TRUE;
    DWORD err = GetLastError();
    if (!IsCurrentProcess(h)) { SetLastError(err); return FALSE; }
    return FallbackEnum(mods, cb, needed, err);
}

static BOOL WINAPI Hook_GetModuleInformation(HANDLE h, HMODULE m, LPMODULEINFO info, DWORD cb)
{
    if (!g_force_fallback && o_GetModuleInformation && o_GetModuleInformation(h, m, info, cb)) return TRUE;
    DWORD err = GetLastError();
    if (!IsCurrentProcess(h) || !info || cb < sizeof(MODULEINFO)) { SetLastError(err); return FALSE; }
    if (!m) m = PebImageBase();
    auto nt = GetNtHeaders(m);
    LONG call = InterlockedIncrement(&g_fallback_info_calls);
    if (!nt)
    {
        if (call <= 20) Log("GetModuleInformation(%p) failed (err=%lu) and module has no valid PE header", m, err);
        SetLastError(err);
        return FALSE;
    }
    info->lpBaseOfDll = m;
    info->SizeOfImage = nt->OptionalHeader.SizeOfImage;
    info->EntryPoint = nt->OptionalHeader.AddressOfEntryPoint ? (BYTE*)m + nt->OptionalHeader.AddressOfEntryPoint : nullptr;
    if (call <= 20) Log("GetModuleInformation(%p) failed (err=%lu) -> fallback size=0x%08lX", m, err, info->SizeOfImage);
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

static DWORD WINAPI Hook_GetModuleBaseNameW(HANDLE h, HMODULE m, LPWSTR out, DWORD cch)
{
    if (!g_force_fallback && o_GetModuleBaseNameW)
    {
        DWORD r = o_GetModuleBaseNameW(h, m, out, cch);
        if (r) return r;
    }
    DWORD err = GetLastError();
    if (!IsCurrentProcess(h) || !out || !cch) { SetLastError(err); return 0; }
    if (!GetModuleBaseNameFallbackW(m, out, cch)) { SetLastError(err); return 0; }
    if (InterlockedIncrement(&g_fallback_name_calls) <= 20) Log("GetModuleBaseNameW(%p) failed (err=%lu) -> fallback '%ls'", m, err, out);
    SetLastError(ERROR_SUCCESS);
    return (DWORD)wcslen(out);
}

static DWORD WINAPI Hook_GetModuleBaseNameA(HANDLE h, HMODULE m, LPSTR out, DWORD cch)
{
    if (!g_force_fallback && o_GetModuleBaseNameA)
    {
        DWORD r = o_GetModuleBaseNameA(h, m, out, cch);
        if (r) return r;
    }
    DWORD err = GetLastError();
    if (!IsCurrentProcess(h) || !out || !cch) { SetLastError(err); return 0; }
    wchar_t wname[MAX_PATH];
    if (!GetModuleBaseNameFallbackW(m, wname, ARRAYSIZE(wname))) { SetLastError(err); return 0; }
    int n = WideCharToMultiByte(CP_ACP, 0, wname, -1, out, (int)cch, nullptr, nullptr);
    if (n <= 0) { out[cch - 1] = 0; n = (int)strlen(out) + 1; }
    if (InterlockedIncrement(&g_fallback_name_calls) <= 20) Log("GetModuleBaseNameA(%p) failed (err=%lu) -> fallback '%s'", m, err, out);
    SetLastError(ERROR_SUCCESS);
    return (DWORD)strlen(out);
}

static DWORD WINAPI Hook_GetModuleFileNameExW(HANDLE h, HMODULE m, LPWSTR out, DWORD cch)
{
    if (!g_force_fallback && o_GetModuleFileNameExW)
    {
        DWORD r = o_GetModuleFileNameExW(h, m, out, cch);
        if (r) return r;
    }
    DWORD err = GetLastError();
    if (!IsCurrentProcess(h) || !out || !cch) { SetLastError(err); return 0; }
    DWORD r = GetModuleFileNameW(m, out, cch);
    if (!r) { SetLastError(err); return 0; }
    if (InterlockedIncrement(&g_fallback_name_calls) <= 20) Log("GetModuleFileNameExW(%p) failed (err=%lu) -> fallback '%ls'", m, err, out);
    return r;
}

static DWORD WINAPI Hook_GetModuleFileNameExA(HANDLE h, HMODULE m, LPSTR out, DWORD cch)
{
    if (!g_force_fallback && o_GetModuleFileNameExA)
    {
        DWORD r = o_GetModuleFileNameExA(h, m, out, cch);
        if (r) return r;
    }
    DWORD err = GetLastError();
    if (!IsCurrentProcess(h) || !out || !cch) { SetLastError(err); return 0; }
    DWORD r = GetModuleFileNameA(m, out, cch);
    if (!r) { SetLastError(err); return 0; }
    if (InterlockedIncrement(&g_fallback_name_calls) <= 20) Log("GetModuleFileNameExA(%p) failed (err=%lu) -> fallback '%s'", m, err, out);
    return r;
}

struct HookDef { const char* name; void* hook; };
static const HookDef kHooks[] = {
    {"K32EnumProcessModules", (void*)&Hook_EnumProcessModules},
    {"EnumProcessModules", (void*)&Hook_EnumProcessModules},
    {"K32EnumProcessModulesEx", (void*)&Hook_EnumProcessModulesEx},
    {"EnumProcessModulesEx", (void*)&Hook_EnumProcessModulesEx},
    {"K32GetModuleInformation", (void*)&Hook_GetModuleInformation},
    {"GetModuleInformation", (void*)&Hook_GetModuleInformation},
    {"K32GetModuleBaseNameA", (void*)&Hook_GetModuleBaseNameA},
    {"GetModuleBaseNameA", (void*)&Hook_GetModuleBaseNameA},
    {"K32GetModuleBaseNameW", (void*)&Hook_GetModuleBaseNameW},
    {"GetModuleBaseNameW", (void*)&Hook_GetModuleBaseNameW},
    {"K32GetModuleFileNameExA", (void*)&Hook_GetModuleFileNameExA},
    {"GetModuleFileNameExA", (void*)&Hook_GetModuleFileNameExA},
    {"K32GetModuleFileNameExW", (void*)&Hook_GetModuleFileNameExW},
    {"GetModuleFileNameExW", (void*)&Hook_GetModuleFileNameExW},
};

static void* FindHook(const char* name)
{
    for (auto& h : kHooks)
        if (strcmp(h.name, name) == 0) return h.hook;
    return nullptr;
}

static bool PatchSlot(ULONG_PTR* slot, void* value)
{
    DWORD old;
    if (!VirtualProtect(slot, sizeof(*slot), PAGE_READWRITE, &old)) return false;
    *slot = (ULONG_PTR)value;
    VirtualProtect(slot, sizeof(*slot), old, &old);
    return true;
}

static int PatchThunks(BYTE* base, IMAGE_THUNK_DATA64* names, IMAGE_THUNK_DATA64* iat, const char* dll)
{
    int patched = 0;
    for (; names->u1.AddressOfData; ++names, ++iat)
    {
        if (IMAGE_SNAP_BY_ORDINAL64(names->u1.Ordinal)) continue;
        auto ibn = (IMAGE_IMPORT_BY_NAME*)(base + names->u1.AddressOfData);
        void* hook = FindHook((const char*)ibn->Name);
        if (!hook) continue;
        if (PatchSlot((ULONG_PTR*)&iat->u1.Function, hook))
        {
            ++patched;
            Log("  patched %s!%s", dll, (const char*)ibn->Name);
        }
        else
        {
            Log("  FAILED to patch %s!%s (err=%lu)", dll, (const char*)ibn->Name, GetLastError());
        }
    }
    return patched;
}

static int PatchModuleImports(HMODULE mod)
{
    auto base = (BYTE*)mod;
    auto nt = GetNtHeaders(mod);
    if (!nt) return 0;
    int patched = 0;

    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir.VirtualAddress)
    {
        for (auto imp = (IMAGE_IMPORT_DESCRIPTOR*)(base + dir.VirtualAddress); imp->Name; ++imp)
        {
            if (!imp->OriginalFirstThunk) continue;
            patched += PatchThunks(base, (IMAGE_THUNK_DATA64*)(base + imp->OriginalFirstThunk),
                                   (IMAGE_THUNK_DATA64*)(base + imp->FirstThunk), (const char*)(base + imp->Name));
        }
    }

    auto& ddir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    if (ddir.VirtualAddress)
    {
        // Delay-load slots are resolved lazily; pre-resolving them to our hooks is fine because the
        // hooks never call back through the delay-load helper.
        for (auto d = (IMAGE_DELAYLOAD_DESCRIPTOR*)(base + ddir.VirtualAddress); d->DllNameRVA; ++d)
        {
            if (!d->ImportNameTableRVA || !d->ImportAddressTableRVA) continue;
            patched += PatchThunks(base, (IMAGE_THUNK_DATA64*)(base + d->ImportNameTableRVA),
                                   (IMAGE_THUNK_DATA64*)(base + d->ImportAddressTableRVA), (const char*)(base + d->DllNameRVA));
        }
    }
    return patched;
}

static void ResolveOriginals()
{
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    o_EnumProcessModules = (EnumProcessModules_t)GetProcAddress(k32, "K32EnumProcessModules");
    o_EnumProcessModulesEx = (EnumProcessModulesEx_t)GetProcAddress(k32, "K32EnumProcessModulesEx");
    o_GetModuleInformation = (GetModuleInformation_t)GetProcAddress(k32, "K32GetModuleInformation");
    o_GetModuleBaseNameA = (GetModuleBaseNameA_t)GetProcAddress(k32, "K32GetModuleBaseNameA");
    o_GetModuleBaseNameW = (GetModuleBaseNameW_t)GetProcAddress(k32, "K32GetModuleBaseNameW");
    o_GetModuleFileNameExA = (GetModuleFileNameExA_t)GetProcAddress(k32, "K32GetModuleFileNameExA");
    o_GetModuleFileNameExW = (GetModuleFileNameExW_t)GetProcAddress(k32, "K32GetModuleFileNameExW");
}

// ---------------------------------------------------------------------------------------------
// Loader
// ---------------------------------------------------------------------------------------------
static bool FileExists(const wchar_t* p)
{
    DWORD a = GetFileAttributesW(p);
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

static void LoadUE4SS(HMODULE self)
{
    wchar_t dir[MAX_PATH * 2];
    DWORD n = GetModuleFileNameW(self, dir, ARRAYSIZE(dir));
    if (!n || n >= ARRAYSIZE(dir)) return;
    wchar_t* slash = wcsrchr(dir, L'\\');
    if (slash) *slash = 0;

    // Log goes into ue4ss\ if that folder exists, else next to this dll.
    wchar_t ue4ss_dir[MAX_PATH * 2];
    swprintf_s(ue4ss_dir, L"%s\\ue4ss", dir);
    DWORD da = GetFileAttributesW(ue4ss_dir);
    bool has_ue4ss_dir = da != INVALID_FILE_ATTRIBUTES && (da & FILE_ATTRIBUTE_DIRECTORY);
    swprintf_s(g_log_path, L"%s\\UE4SS-HVFix.log", has_ue4ss_dir ? ue4ss_dir : dir);
    DeleteFileW(g_log_path);

    Log("UE4SS-HVFix proxy loaded into pid %lu, exe base %p", GetCurrentProcessId(), PebImageBase());

    if (wcsstr(GetCommandLineW(), L"--disable-ue4ss"))
    {
        Log("--disable-ue4ss on command line, not loading UE4SS");
        return;
    }

    wchar_t path[MAX_PATH * 2];
    swprintf_s(path, L"%s\\ue4ss\\UE4SS.dll", dir);
    if (!FileExists(path)) swprintf_s(path, L"%s\\UE4SS.dll", dir);
    if (!FileExists(path))
    {
        Log("UE4SS.dll not found (looked in ue4ss\\ and next to dwmapi.dll)");
        MessageBoxW(nullptr, L"UE4SS-HVFix: UE4SS.dll not found in ue4ss\\ folder.", L"UE4SS Error", MB_OK | MB_ICONERROR);
        return;
    }

    ResolveOriginals();
    {
        wchar_t v[8] = {};
        if (GetEnvironmentVariableW(L"UE4SS_HVFIX_FORCE", v, ARRAYSIZE(v)) && v[0] == L'1') g_force_fallback = true;
        if (g_force_fallback) Log("UE4SS_HVFIX_FORCE=1: always using fallback implementations");
    }

    // Quick self-test so the log shows whether the original API is broken in this process.
    {
        HMODULE tmp[4];
        DWORD need = 0;
        BOOL ok = o_EnumProcessModules ? o_EnumProcessModules(GetCurrentProcess(), tmp, sizeof(tmp), &need) : FALSE;
        Log("self-test K32EnumProcessModules: %s (err=%lu, needed=%lu)", ok ? "OK" : "FAILED", ok ? 0 : GetLastError(), need);
    }

    Log("loading %ls", path);
    HMODULE ue4ss = LoadLibraryW(path);
    if (!ue4ss)
    {
        DWORD e = GetLastError();
        Log("LoadLibrary failed, err=%lu", e);
        MessageBoxW(nullptr, L"UE4SS-HVFix: failed to load UE4SS.dll (see UE4SS-HVFix.log).", L"UE4SS Error", MB_OK | MB_ICONERROR);
        return;
    }
    // UE4SS starts its main thread from DllMain; that thread cannot run until we leave our DllMain
    // (loader lock), so patching here happens before UE4SS enumerates modules.
    int patched = PatchModuleImports(ue4ss);
    Log("UE4SS.dll loaded at %p, %d import slots patched", ue4ss, patched);
}

BOOL APIENTRY DllMain(HMODULE self, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(self);
        InitializeCriticalSection(&g_log_cs);
        InitializeCriticalSection(&g_enum_cs);
        LoadUE4SS(self);
    }
    return TRUE;
}
