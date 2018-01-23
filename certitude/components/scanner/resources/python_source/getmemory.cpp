/*
 * On snapshot:
 * https://msdn.microsoft.com/en-us/library/windows/desktop/ms686701%28v=vs.85%29.aspx
 * on all current running process:
 * https://msdn.microsoft.com/en-us/library/windows/desktop/ms682623%28v=vs.85%29.aspx
 */

// link with psapi.dll

#include <Windows.h>
#include <Psapi.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <tchar.h>

// for windows 8, OpenProcess is in Processthreadapi.h


// ID PID PPID PROCESS_NAME BASE_ADDRESS SIZE READ WRITE EXECUTE COPY_ON_WRITE
#define FORMAT TEXT("%lu\t%lu\t%d\t%s\t%p\t%lu\t%d\t%d\t%d\t%d\n")

void printline(HANDLE hProcess, DWORD dProcessId, PTCHAR szFileName, const MEMORY_BASIC_INFORMATION* pInfo);
int getPPID(DWORD pid);

void printline(HANDLE hProcess, DWORD dProcessId, PTCHAR szFileName, const MEMORY_BASIC_INFORMATION* pInfo)
{
    static unsigned long id = 1;
    int dParentProcessId = getPPID(dProcessId);
    BOOL read = FALSE;
    BOOL write = FALSE;
    BOOL exec = FALSE;
    BOOL cop = FALSE;

    if ((pInfo->AllocationProtect & PAGE_READONLY))
    {
        read = TRUE;
    }
    else if ((pInfo->AllocationProtect & PAGE_READWRITE))
    {
        read = TRUE;
        write = TRUE;
    }
    else if ((pInfo->AllocationProtect & PAGE_WRITECOPY))
    {
        read = TRUE;
        write = TRUE;
        cop = TRUE;
    }
    else if ((pInfo->AllocationProtect & PAGE_EXECUTE))
    {
        exec = TRUE;
    }
    else if ((pInfo->AllocationProtect & PAGE_EXECUTE_READ))
    {
        read = TRUE;
        exec = TRUE;
    }
    else if ((pInfo->AllocationProtect & PAGE_EXECUTE_READWRITE))
    {
        read = TRUE;
        write = TRUE;
        exec = TRUE;
    }
    else if ((pInfo->AllocationProtect & PAGE_EXECUTE_WRITECOPY))
    {
        read = TRUE;
        write = TRUE;
        exec = TRUE;
        cop = TRUE;
    }
    else if (!(pInfo->AllocationProtect & PAGE_NOACCESS) && pInfo->AllocationProtect)
    {
        _tprintf("ERROR: unknown protection for page: %lu\n", pInfo->AllocationProtect);
        // error: unknown setting for page
    }
    /*
     * info.BaseAddress; // PVOID
     * info.AllocationBase; // PVOID
     * info.AllocationProtect; //DWORD: Flags lors de l'allocation
     * info.RegionSize; // SIZE_T
     * info.State; // DWORD: Flags
     * info.Protect; //DWORD: Flags courant
     * info.Type; DWORD
     */
    _tprintf(FORMAT, ++id, dProcessId, dParentProcessId, szFileName,
             pInfo->BaseAddress, pInfo->RegionSize,
             read, write, exec, cop);
}

int getPPID(DWORD pid)
{
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = { 0 };
    pe.dwSize = sizeof (PROCESSENTRY32);

    if (Process32First(h, &pe))
    {
        do
        {
            if (pe.th32ProcessID == pid)
            {
                CloseHandle(h);
                return pe.th32ParentProcessID;
            }
        } while (Process32Next(h, &pe));
    }

    CloseHandle(h);
    return -1;
}

int main(void)
{
    // how can we know the number of process
    DWORD aProcessIds[1024];
    DWORD cResultSize;

    // enumProcess
    if (!EnumProcesses(aProcessIds, sizeof (aProcessIds), &cResultSize))
    {
        DWORD err = GetLastError();
        _ftprintf(stderr, TEXT("ERROR: can't enum processes: %lu\n"), err);
        return 1;
    }

    DWORD cNbProcess = cResultSize / sizeof (DWORD);
    // iter on them
    for (DWORD i = 0; i < cNbProcess; ++i)
    {
        // OpenProcess
        DWORD dProcessId = aProcessIds[i];
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dProcessId);
        if (!hProcess)
        {
            DWORD err = GetLastError();
            _ftprintf(stderr, TEXT("ERROR: can't open Process with pid %lu: %lu\n"), dProcessId, err);
            continue;
        }

        TCHAR tmpFileName[MAX_PATH] = { 0 };
        PTCHAR szFileName = NULL;
        if (!GetModuleFileNameEx(hProcess, 0, szFileName, sizeof(szFileName)/sizeof(TCHAR)))
        {
            DWORD err = GetLastError();
            _ftprintf(stderr, TEXT("ERROR: can't get module name for pid %lu: %lu\n"), dProcessId, err);
            szFileName = TEXT("<unknown>");
        }
        else
        {
            szFileName = tmpFileName;
        }

        // Iterate on pages
        long unsigned int p = 0;
        MEMORY_BASIC_INFORMATION info;
        while (1)
        {
            // prevent overflow on MmUserProbeAddress
            if (p >= (long unsigned int)0x7FFF0000)
                break;
            SIZE_T tmp = VirtualQueryEx(hProcess, (LPCVOID)p, &info, sizeof (info));
            if (!tmp)
            {
                DWORD err = GetLastError();
                _ftprintf(stderr, TEXT("ERROR: can't query virtual information for pid %lu in address %p: %lu\n"), dProcessId, (LPCVOID)p, err);
                break;
            }
            // stop when we didn't read the page information
            if (sizeof (info) != tmp)
                break;
            printline(hProcess, dProcessId, szFileName, &info);
            p += info.RegionSize;
        }
        CloseHandle(hProcess);
    }
    return 0;
}
