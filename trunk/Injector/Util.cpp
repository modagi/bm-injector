/************************************************************************
    This file is part of BM Injector.

	FILE : Util.cpp
	DESC : 

	Author : Sungjin Kim
	E-Mail : modagi@gmail.com
	Date   : 08/23/2011
	
	BM Injector is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
************************************************************************/

#include "StdAfx.h"
#include <tlhelp32.h>

#include "InjectionInfo.h"
#include "InjectionCode.h"
#include "Datas.h"
#include "Util.h"

DWORD g_dwPreFuncAddr = 0;

int GetOSVersion(BOOL bMajor)
{
	OSVERSIONINFO osver = {0, };

	osver.dwOSVersionInfoSize = sizeof(osver);

	GetVersionEx(&osver);

	return osver.dwMajorVersion; 
}

BOOL InjectDll(DWORD dwPid, LPCTSTR szDllName)
{
	HANDLE					hProcess = NULL;
	HANDLE					hMod = NULL;
	HANDLE					hThread = NULL;
	LPVOID					pRemoteBuf = NULL;
	DWORD					dwBufSize = lstrlen(szDllName)+1;
	LPTHREAD_START_ROUTINE	pThreadProc = {0, };

	HANDLE					hProcessToken = NULL;
	TOKEN_PRIVILEGES		stOldToken = {0, };
	DWORD					dwOldCount = 0;

	if ( !SetDebugPrivilege(&hProcessToken, &stOldToken, &dwOldCount) )
	{
		WRITE_LOG(LOG_LEVEL_1, "SetDebugPrivilege was failed.");
		return FALSE;
	}

	if ( !(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid)) )
	{
		WRITE_LOG(LOG_LEVEL_1, "OpenProcess was failed.");
		RestorePrivilege(hProcessToken, stOldToken, dwOldCount);
		return FALSE;
	}

	if ( !RestorePrivilege(hProcessToken, stOldToken, dwOldCount) )
	{
		WRITE_LOG(LOG_LEVEL_1, "RestorePrivilege was failed.");
		return FALSE;
	}
	
	if ( !(pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE)) )
	{
		WRITE_LOG(LOG_LEVEL_1, "VirtualAllocEx was failed.");
		return FALSE;
	}

	if ( !WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllName, dwBufSize, NULL) )
	{
		WRITE_LOG(LOG_LEVEL_1, "WriteProcessMemory was failed.");
		VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}

	if ( !(hMod = GetModuleHandle("kernel32.dll")) )
	{
		WRITE_LOG(LOG_LEVEL_1, "GetModuleHandle was failed.");
		VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}

	if ( !(pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress((HINSTANCE)hMod, "LoadLibraryA")) )
	{
		WRITE_LOG(LOG_LEVEL_1, "GetProcAddress was failed.");
		VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}

	if ( GetOSVersion() < 6 )
	{
		if ( !(hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL)) )
		{
			WRITE_LOG(LOG_LEVEL_1, "CreateRemoteThread was failed.");
			VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
			CloseHandle(hProcess);
			return FALSE;
		}
	}
	else
	{
		static t_fNtCreateThreadEx fNtCreateThreadEx = (t_fNtCreateThreadEx)GetProcAddress(LoadLibrary("ntdll.dll"), "NtCreateThreadEx");

		if ( fNtCreateThreadEx == NULL )
		{
			WRITE_LOG(LOG_LEVEL_1, "GetProcAddress was failed.");
			VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
			CloseHandle(hProcess);
			return FALSE;
		}

		fNtCreateThreadEx(&hThread,
			0x1FFFFF,
			NULL,
			hProcess,
			pThreadProc,
			pRemoteBuf,
			FALSE,
			NULL,
			NULL,
			NULL,
			NULL);

		if ( hThread == NULL)
		{
			WRITE_LOG(LOG_LEVEL_1, "NtCreateThreadEx was failed.");
			DWORD dwErr = GetLastError();
			VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
			CloseHandle(hProcess);
			return FALSE;
		}
	}

	if(WaitForSingleObject(hThread, INFINITE))
	{
		WRITE_LOG(LOG_LEVEL_1, "WaitForSingleObject was failed.");
		VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}

	VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
	CloseHandle(hProcess);

	return TRUE;
}

BOOL EjectDll(DWORD dwPID, LPCTSTR szDllName)
{
	BOOL	bMore = FALSE;
	BOOL	bFound = FALSE;
	HANDLE	hSnapshot = NULL;
	HANDLE	hProcess = NULL;
	HANDLE	hThread = NULL;
	HMODULE	hModule = NULL;
	MODULEENTRY32 me = { sizeof(me) };
	LPTHREAD_START_ROUTINE pThreadProc = {0, };

	HANDLE					hProcessToken	= NULL;
	TOKEN_PRIVILEGES		stOldToken = {0, };
	DWORD					dwOldCount		= 0;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
	if ( hSnapshot == INVALID_HANDLE_VALUE )
	{
		WRITE_LOG(LOG_LEVEL_1, "CreateToolhelp32Snapshot was failed.");
		return FALSE;
	}

	for ( bMore = Module32First(hSnapshot, &me); bMore; bMore = Module32Next(hSnapshot, &me) )
	{
		if ( !_stricmp((LPCTSTR)me.szModule, (LPCTSTR)(szDllName + strlen(szDllName) - strlen(me.szModule))) )
		{
			bFound = TRUE;
			break;
		}
	}

	if ( !bFound )
	{
		MessageBox(NULL, "The DLL is not exist", "", MB_OK);
		CloseHandle(hSnapshot);
		return FALSE;
	}

	if ( !SetDebugPrivilege(&hProcessToken, &stOldToken, &dwOldCount) )
	{
		WRITE_LOG(LOG_LEVEL_1, "SetDebugPrivilege was failed.");
		return FALSE;
	}

	if ( !(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)) )
	{
		WRITE_LOG(LOG_LEVEL_1, "OpenProcess was failed.");
		RestorePrivilege(hProcessToken, stOldToken, dwOldCount);
		return FALSE;
	}

	if ( !RestorePrivilege(hProcessToken, stOldToken, dwOldCount) )
	{
		WRITE_LOG(LOG_LEVEL_1, "RestorePrivilege was failed.");
		return FALSE;
	}

	hModule = GetModuleHandle("kernel32.dll");

	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hModule, "FreeLibrary");

	if ( GetOSVersion() < 6 )
	{
		if ( !(hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, me.modBaseAddr, 0, NULL)) )
		{
			WRITE_LOG(LOG_LEVEL_1, "CreateRemoteThread was failed.");
			return FALSE;
		}
	}
	else
	{
		static t_fNtCreateThreadEx fNtCreateThreadEx = (t_fNtCreateThreadEx)GetProcAddress(LoadLibrary("ntdll.dll"), "NtCreateThreadEx");

		if ( fNtCreateThreadEx == NULL )
		{
			WRITE_LOG(LOG_LEVEL_1, "GetProcAddress was failed.");
			return FALSE;
		}

		fNtCreateThreadEx(&hThread,
			0x1FFFFF,
			NULL,
			hProcess,
			pThreadProc,
			me.modBaseAddr,
			FALSE,
			NULL,
			NULL,
			NULL,
			NULL);

		if ( hThread == NULL)
		{
			WRITE_LOG(LOG_LEVEL_1, "NtCreateThreadEx was failed.");
			return FALSE;
		}
	}

	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);
	CloseHandle(hProcess);
	CloseHandle(hSnapshot);

	return TRUE;
}

BOOL InjectCode(DWORD dwPID, LPCTSTR szDllPath, CInjectionInfo &info)
{
    HANDLE          hProcess        = NULL;
    HANDLE          hThread         = NULL;
    DWORD           dwSize          = 0;
	DWORD			dwFuncSize		= 0;

	HANDLE					hProcessToken	= NULL;
	TOKEN_PRIVILEGES		stOldToken = {0, };
	DWORD					dwOldCount		= 0;
/*
	PVOID			pAddrThreadProc = NULL;
	PVOID			pAddrEjectThreadProc = NULL;

	LPVOID pAddrHookAPI = NULL;
	LPVOID pAddrUnhookAPI = NULL;
	LPVOID pAddrMyZwResumeThread = NULL;
	LPVOID pAddrOrgBytes = NULL;
	LPVOID pAddrThreadParam = NULL;
	LPVOID pAddrGetOSVersion = NULL;
	LPVOID pAddrRestorePrivilege = NULL;
	LPVOID pAddrSetDebugPrivilege = NULL;
*/
	LPVOID pAddrInjectDll = NULL;

 //   GLOBAL_VAR *pstGlobalVar = NULL;

	if ( !SetDebugPrivilege(&hProcessToken, &stOldToken, &dwOldCount) )
	{
		WRITE_LOG(LOG_LEVEL_1, "SetDebugPrivilege was failed.");
		return FALSE;
	}

    if ( !(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)) )             // dwProcessId
    {
		WRITE_LOG(LOG_LEVEL_1, "OpenProcess was failed.");
        RestorePrivilege(hProcessToken, stOldToken, dwOldCount);
        return FALSE;
    }

	if ( !RestorePrivilege(hProcessToken, stOldToken, dwOldCount) )
	{
		WRITE_LOG(LOG_LEVEL_1, "RestorePrivilege was failed.");
		goto END_PROCESS_OF_INJECTCODE;
	}


	if ( !info.SetAddrGlobalVar(AllocGlobalVars(hProcess)) )
	{
		WRITE_LOG(LOG_LEVEL_1, "SetAddrGlobalVar was failed.");
		goto END_PROCESS_OF_INJECTCODE;
	}

	if ( !info.SetAddrPreFunc(InjectCode_MyPreFunction(hProcess)) )
	{
		WRITE_LOG(LOG_LEVEL_1, "SetAddrPreFunc was failed.");
		goto END_PROCESS_OF_INJECTCODE;
	}

	if ( !info.SetAddrHookAPI(InjectCode_HookAPI(hProcess)) )
	{
		WRITE_LOG(LOG_LEVEL_1, "SetAddrHookAPI was failed.");
		goto END_PROCESS_OF_INJECTCODE;
	}

	if ( !info.SetAddrUnhookAPI(InjectCode_UnhookAPI(hProcess)) )
	{
		WRITE_LOG(LOG_LEVEL_1, "SetAddrUnhookAPI was failed.");
		goto END_PROCESS_OF_INJECTCODE;
	}

	if ( !info.SetAddrGetOSVersion(InjectCode_GetOSVersion(hProcess)) )
	{
		WRITE_LOG(LOG_LEVEL_1, "SetAddrGetOSVersion was failed.");
		goto END_PROCESS_OF_INJECTCODE;
	}

	if ( !info.SetAddrSetDebugPrivilege(InjectCode_SetDebugPrivilege(hProcess)) )
	{
		WRITE_LOG(LOG_LEVEL_1, "SetAddrSetDebugPrivilege was failed.");
		goto END_PROCESS_OF_INJECTCODE;
	}

	if ( !info.SetAddrRestorePrivilege(InjectCode_RestorePrivilege(hProcess)) )
	{
		WRITE_LOG(LOG_LEVEL_1, "SetAddrRestorePrivilege was failed.");
		goto END_PROCESS_OF_INJECTCODE;
	}

	if ( !info.SetAddrInjectDll(InjectCode_InjectDll(hProcess, info.GetAddrGetOSVersion(), info.GetAddrSetDebugPrivilege(), info.GetAddrRestorePrivilege())) )
	{
		WRITE_LOG(LOG_LEVEL_1, "SetAddrInjectDll was failed.");
		goto END_PROCESS_OF_INJECTCODE;
	}

	if ( !info.SetAddrMyZwResumeThread(InjectCode_MyZwResumeThread(hProcess, szDllPath, info.GetAddrGlobalVar(), info.GetAddrHookAPI(), info.GetAddrUnhookAPI(), info.GetAddrInjectDll())) )
	{
		WRITE_LOG(LOG_LEVEL_1, "SetAddrMyZwResumeThread was failed.");
		goto END_PROCESS_OF_INJECTCODE;
	}

	if ( !info.SetAddrThreadProc(InjectCode_ThreadProc(hProcess)) )
	{
		WRITE_LOG(LOG_LEVEL_1, "SetAddrThreadProc was failed.");
		goto END_PROCESS_OF_INJECTCODE;
	}

	if ( !info.SetAddrEjectThreadProc(InjectCode_EjectThreadProc(hProcess)) )
	{
		WRITE_LOG(LOG_LEVEL_1, "SetAddrEjectThreadProc was failed.");
		goto END_PROCESS_OF_INJECTCODE;
	}

	if ( !info.SetAddrThreadParam(PrepareInjectThreadParam(hProcess, info.GetAddrHookAPI(), info.GetAddrMyZwResumeThread(), (PBYTE)info.GetAddrGlobalVar())) )
	{
		WRITE_LOG(LOG_LEVEL_1, "SetAddrThreadParam was failed.");
		goto END_PROCESS_OF_INJECTCODE;
	}

	if( !(hThread = CreateRemoteThread(hProcess,
                                       NULL,
                                       0,
                                       (LPTHREAD_START_ROUTINE)info.GetAddrThreadProc(),
                                       info.GetAddrThreadParam(),
                                       0,
                                       NULL)) )
	{
		WRITE_LOG(LOG_LEVEL_1, "CreateRemoteThread was failed.");
		goto END_PROCESS_OF_INJECTCODE;
	}


    WaitForSingleObject(hThread, INFINITE);	

    CloseHandle(hThread);
END_PROCESS_OF_INJECTCODE:
    CloseHandle(hProcess);

    return TRUE;
}

BOOL EjectCode(DWORD dwPID, CInjectionInfo &info)
{
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;

	HANDLE					hProcessToken	= NULL;
	TOKEN_PRIVILEGES		stOldToken = {0, };
	DWORD					dwOldCount		= 0;


	if ( !SetDebugPrivilege(&hProcessToken, &stOldToken, &dwOldCount) )
	{
		WRITE_LOG(LOG_LEVEL_1, "SetDebugPrivilege was failed.");
		goto END_PROCESS_OF_EJECTCODE;
	}

    if ( !(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)) )
    {
		WRITE_LOG(LOG_LEVEL_1, "OpenProcess was failed.");
        RestorePrivilege(hProcessToken, stOldToken, dwOldCount);
        goto END_PROCESS_OF_EJECTCODE;
    }
	 
	if ( !RestorePrivilege(hProcessToken, stOldToken, dwOldCount) )
	{
		WRITE_LOG(LOG_LEVEL_1, "RestorePrivilege was failed.");
		goto END_PROCESS_OF_EJECTCODE;
	}

	if ( !PrepareEjectThreadParam(hProcess, info.GetAddrThreadParam(), info.GetAddrUnhookAPI()) )
	{
		WRITE_LOG(LOG_LEVEL_1, "PrepareEjectThreadParam was failed.");
		goto END_PROCESS_OF_EJECTCODE;
	}

	if( !(hThread = CreateRemoteThread(hProcess,
                                       NULL,
                                       0,
                                       (LPTHREAD_START_ROUTINE)info.GetAddrEjectThreadProc(),
                                       info.GetAddrThreadParam(),
                                       0,
                                       NULL)) )
	{
		WRITE_LOG(LOG_LEVEL_1, "CreateRemoteThread was failed.");
		goto END_PROCESS_OF_EJECTCODE;
	}

    WaitForSingleObject(hThread, INFINITE);

	Sleep(100);

	if ( !info.Release(hProcess) )
	{
		CloseHandle(hProcess);
		goto END_PROCESS_OF_EJECTCODE;
	}
END_PROCESS_OF_EJECTCODE:
	CloseHandle(hProcess);

	return TRUE;
}

BOOL SetDebugPrivilege(HANDLE *phProcessToken, TOKEN_PRIVILEGES *pOldToken, DWORD *pdwOldCount)
{
	TOKEN_PRIVILEGES stNewToken = {0, };

	if ( !OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, phProcessToken) )
	{
		ErrorMessageBox("OpenProcessToken");
		return FALSE;
	}

	if ( !LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &(stNewToken.Privileges[0].Luid)) )
	{
		ErrorMessageBox("LookupPrivilegeValue");
		return FALSE;
	}

	stNewToken.PrivilegeCount = 1;
	stNewToken.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if ( !AdjustTokenPrivileges(*phProcessToken, FALSE, &stNewToken, sizeof(TOKEN_PRIVILEGES), pOldToken, pdwOldCount) )
	{
		ErrorMessageBox("AdjustTokenPrivileges");
		return FALSE;
	}

	return TRUE;
}

BOOL RestorePrivilege(HANDLE hProcessToken, TOKEN_PRIVILEGES stOldToken, DWORD dwOldCount)
{
	if ( !AdjustTokenPrivileges(hProcessToken, FALSE, &stOldToken, dwOldCount, NULL, NULL) )
	{
		ErrorMessageBox("AdjustTokenPrivileges");
		return FALSE;
	}

	return TRUE;
}

void ErrorMessageBox(LPCTSTR lpszErrCaption)
{
	LPVOID lpErrMsg = NULL;

	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		GetLastError(),
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)lpErrMsg,
		0,
		NULL);

	MessageBox(NULL, (LPCTSTR)lpErrMsg, lpszErrCaption, MB_OK);

	LocalFree(lpErrMsg);
}

LPVOID AllocGlobalVars(HANDLE hProcess)
{
	LPVOID		pAllocated		= NULL;
	LPVOID		pData			= NULL;
	char		szString[64]	= {0, };
	DWORD		dwData			= 0;
	DWORD		*pStructPtr		= NULL;

	if( !(pAllocated = (DWORD*)VirtualAllocEx(hProcess, NULL, sizeof(GLOBAL_VAR), MEM_COMMIT, PAGE_EXECUTE_READWRITE)) )
		return NULL;

	TRACE("AllocGlobalVars # Allocated address : 0x%08X\n", (DWORD)pAllocated);

	pStructPtr = (DWORD*)pAllocated;

	if( !(pData = (DWORD*)VirtualAllocEx(hProcess, NULL, 5, MEM_COMMIT, PAGE_EXECUTE_READWRITE)) )
	{
		WRITE_LOG(LOG_LEVEL_1, "VirtualAllocEx was failed.");
		return NULL;
	}
	const char *ptr = __func__;
	dwData = (DWORD)pData;

	if( !WriteProcessMemory(hProcess, pStructPtr++, &dwData, sizeof(dwData), NULL) )
	{
		WRITE_LOG(LOG_LEVEL_1, "VirtualAllocEx was failed.");
        return NULL;
	}

	dwData = (DWORD)AllocStringVar(hProcess, "ntdll.dll");

	if( !WriteProcessMemory(hProcess, pStructPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	dwData = (DWORD)AllocStringVar(hProcess, "NtCreateThreadEx");

	if( !WriteProcessMemory(hProcess, pStructPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	dwData = (DWORD)AllocStringVar(hProcess, "kernel32.dll");

	if( !WriteProcessMemory(hProcess, pStructPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	dwData = (DWORD)AllocStringVar(hProcess, "LoadLibraryA");

	if( !WriteProcessMemory(hProcess, pStructPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	dwData = (DWORD)AllocStringVar(hProcess, "AdvApi32.dll");

	if( !WriteProcessMemory(hProcess, pStructPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	return pAllocated;
}

LPVOID AllocStringVar(HANDLE hProcess, LPCTSTR szStr)
{
	LPVOID		pAllocated		= NULL;
	DWORD		dwData			= 0;

	if ( szStr == NULL)
		return NULL;

	if( !(pAllocated = (DWORD*)VirtualAllocEx(hProcess, NULL, strlen(szStr)+1, MEM_COMMIT, PAGE_EXECUTE_READWRITE)) )
		return NULL;

	if( !WriteProcessMemory(hProcess, pAllocated, szStr, strlen(szStr)+1, NULL) )
        return NULL;

	return pAllocated;
}

LPVOID InjectCode_MyPreFunction(HANDLE hProcess)
{
	DWORD			*pAllocated		= NULL;
	DWORD			*pPtr			= NULL;
	DWORD			dwSize			= 0;
	DWORD			dwData			= 0;
	DWORD			dwFuncSize		= 0;


	dwFuncSize = (DWORD)IC_Boundary - (DWORD)IC_MyPreFunction;
    dwSize = dwFuncSize;

    if( !(pAllocated = (DWORD*)VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE)) )
		return NULL;

	TRACE("InjectCode_MyPreFunction # Allocated address : 0x%08X\n", (DWORD)pAllocated);

	pPtr = pAllocated;

	if( !WriteProcessMemory(hProcess, pPtr, IC_MyPreFunction, dwFuncSize, NULL) )
        return NULL;

	g_dwPreFuncAddr = (DWORD)pAllocated;

	return pAllocated;
}

LPVOID InjectCode_HookAPI(HANDLE hProcess)
{
	DWORD			*pAllocated		= NULL;
	DWORD			*pPtr			= NULL;
	DWORD			dwSize			= 0;
	DWORD			dwData			= 0;
	DWORD			dwDataCount		= 0;
	DWORD			dwFuncSize		= 0;
    HMODULE         hMod			= GetModuleHandleA("kernel32.dll");
	BYTE			pPreFuncCode[8] = {0, };

	dwDataCount = 4;
	dwFuncSize = (DWORD)IC_UnhookAPI - (DWORD)IC_HookAPI;
    dwSize = dwFuncSize + dwDataCount*sizeof(PVOID) + 4*sizeof(PVOID);

    if( !(pAllocated = (DWORD*)VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE)) )
		return NULL;

	TRACE("InjectCode_HookAPI # Allocated address : 0x%08X\n", (DWORD)pAllocated);

	GetCallCode(pPreFuncCode, (DWORD)pAllocated);

	pPtr = pAllocated;

	if( !WriteProcessMemory(hProcess, pPtr++, &pPreFuncCode, sizeof(pPreFuncCode), NULL) )
        return NULL;

	pPtr++;
	
	dwData = (DWORD)GetProcAddress(hMod, "GetModuleHandleA");

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	dwData = (DWORD)GetProcAddress(hMod, "GetProcAddress");

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	dwData = (DWORD)GetProcAddress(hMod, "VirtualProtect");

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	hMod = GetModuleHandleA("ntdll.dll");
	dwData = (DWORD)GetProcAddress(hMod, "memcpy");

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	dwData = BOUNDARY_MARK;

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	if( !WriteProcessMemory(hProcess, pPtr, IC_HookAPI, dwFuncSize, NULL) )
        return NULL;

	return pAllocated;
}

LPVOID InjectCode_UnhookAPI(HANDLE hProcess)
{
	DWORD			*pAllocated		= NULL;
	DWORD			*pPtr			= NULL;
	DWORD			dwSize			= 0;
	DWORD			dwData			= 0;
	DWORD			dwDataCount		= 0;
	DWORD			dwFuncSize		= 0;
    HMODULE         hMod			= GetModuleHandleA("kernel32.dll");
	BYTE			pPreFuncCode[8] = {0, };

	dwDataCount = 4;
	dwFuncSize = (DWORD)IC_MyZwResumeThread - (DWORD)IC_UnhookAPI;
    dwSize = dwFuncSize + dwDataCount*sizeof(PVOID) + 4*sizeof(PVOID);

    if ( !(pAllocated = (DWORD*)VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE)) )
		return NULL;

	TRACE("InjectCode_UnhookAPI # Allocated address : 0x%08X\n", (DWORD)pAllocated);

	GetCallCode(pPreFuncCode, (DWORD)pAllocated);

	pPtr = pAllocated;

	if ( !WriteProcessMemory(hProcess, pPtr++, &pPreFuncCode, sizeof(pPreFuncCode), NULL) )
        return NULL;

	pPtr++;
	
	dwData = (DWORD)GetProcAddress(hMod, "GetModuleHandleA");

	if ( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	dwData = (DWORD)GetProcAddress(hMod, "GetProcAddress");

	if ( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	dwData = (DWORD)GetProcAddress(hMod, "VirtualProtect");

	if ( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	hMod = GetModuleHandleA("ntdll.dll");
	dwData = (DWORD)GetProcAddress(hMod, "memcpy");

	if ( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	dwData = BOUNDARY_MARK;

	if ( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	if ( !WriteProcessMemory(hProcess, pPtr, IC_UnhookAPI, dwFuncSize, NULL) )
        return NULL;

	return pAllocated;
}

LPVOID InjectCode_MyZwResumeThread(HANDLE hProcess, LPCTSTR szDllPath, GLOBAL_VAR *pstGlobalVar, LPVOID pAddrHookAPI, LPVOID pAddrUnhookAPI, LPVOID pAddrInjectDll)
{
	DWORD			*pAllocated		= NULL;
	DWORD			*pPtr			= NULL;
	DWORD			dwSize			= 0;
	DWORD			dwData			= 0;
	DWORD			dwDataCount		= 0;
	DWORD			dwFuncSize		= 0;
    HMODULE         hMod			= GetModuleHandleA("kernel32.dll");
	BYTE			pPreFuncCode[8] = {0, };

	dwDataCount = 10;
	dwFuncSize = (DWORD)IC_InjectDll - (DWORD)IC_MyZwResumeThread;
    dwSize = dwFuncSize + dwDataCount*sizeof(PVOID) + 4*sizeof(PVOID);

    if( !(pAllocated = (DWORD*)VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE)) )
		return NULL;

	TRACE("InjectCode_MyZwResumeThread # Allocated address : 0x%08X\n", (DWORD)pAllocated);

	GetCallCode(pPreFuncCode, (DWORD)pAllocated);

	pPtr = pAllocated;

	if( !WriteProcessMemory(hProcess, pPtr++, &pPreFuncCode, sizeof(pPreFuncCode), NULL) )
        return NULL;

	pPtr++;
	
	dwData = 0;

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	dwData = (DWORD)AllocStringVar(hProcess, szDllPath);

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	dwData = (DWORD)pstGlobalVar;

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	dwData = (DWORD)GetProcAddress(hMod, "GetCurrentProcessId");

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	hMod = GetModuleHandle("ntdll.dll");

	dwData = (DWORD)GetProcAddress(hMod, "ZwQueryInformationThread");

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	dwData = (DWORD)GetProcAddress(hMod, "ZwResumeThread");

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	dwData = (DWORD)pAddrInjectDll;

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	dwData = (DWORD)pAddrUnhookAPI;

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	dwData = (DWORD)pAddrHookAPI;

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	dwData = (DWORD)pAllocated;

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	dwData = BOUNDARY_MARK;

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	if( !WriteProcessMemory(hProcess, pPtr, IC_MyZwResumeThread, dwFuncSize, NULL) )
        return NULL;

	return pAllocated;
}

LPVOID InjectCode_InjectDll(HANDLE hProcess, LPVOID pAddrGetOSVersion, LPVOID pAddrSetDebugPrivilege, LPVOID pAddrRestorePrivilege)
{
	DWORD			*pAllocated		= NULL;
	DWORD			*pPtr			= NULL;
	DWORD			dwSize			= 0;
	DWORD			dwData			= 0;
	DWORD			dwDataCount		= 0;
	DWORD			dwFuncSize		= 0;
    HMODULE         hMod			= GetModuleHandleA("ntdll.dll");
	BYTE			pPreFuncCode[8] = {0, };

	dwDataCount = 13;
	dwFuncSize = (DWORD)IC_SetDebugPrivilege - (DWORD)IC_InjectDll;
    dwSize = dwFuncSize + dwDataCount*sizeof(PVOID) + 4*sizeof(PVOID);

    if( !(pAllocated = (DWORD*)VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE)) )
		return NULL;

	TRACE("InjectCode_InjectDll # Allocated address : 0x%08X\n", (DWORD)pAllocated);

	GetCallCode(pPreFuncCode, (DWORD)pAllocated);

	pPtr = pAllocated;

	if( !WriteProcessMemory(hProcess, pPtr++, &pPreFuncCode, sizeof(pPreFuncCode), NULL) )
        return NULL;

	pPtr++;
	
	dwData = (DWORD)pAddrSetDebugPrivilege;

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	dwData = (DWORD)pAddrRestorePrivilege;

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	dwData = (DWORD)pAddrGetOSVersion;

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	dwData = (DWORD)GetProcAddress(hMod, "NtCreateThreadEx");

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	hMod = GetModuleHandleA("kernel32.dll");

	dwData = (DWORD)GetProcAddress(hMod, "lstrlenA");

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	dwData = (DWORD)GetProcAddress(hMod, "CloseHandle");

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	dwData = (DWORD)GetProcAddress(hMod, "VirtualFreeEx");

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	dwData = (DWORD)GetProcAddress(hMod, "WaitForSingleObject");

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	dwData = (DWORD)GetProcAddress(hMod, "LoadLibraryA");

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	dwData = (DWORD)GetProcAddress(hMod, "CreateRemoteThread");

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	dwData = (DWORD)GetProcAddress(hMod, "WriteProcessMemory");

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	dwData = (DWORD)GetProcAddress(hMod, "VirtualAllocEx");

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	dwData = (DWORD)GetProcAddress(hMod, "OpenProcess");

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;


	dwData = BOUNDARY_MARK;

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	if( !WriteProcessMemory(hProcess, pPtr, IC_InjectDll, dwFuncSize, NULL) )
        return NULL;

	return pAllocated;
}

LPVOID InjectCode_SetDebugPrivilege(HANDLE hProcess)
{
	DWORD			*pAllocated		= NULL;
	DWORD			*pPtr			= NULL;
	DWORD			dwSize			= 0;
	DWORD			dwData			= 0;
	DWORD			dwDataCount		= 0;
	DWORD			dwFuncSize		= 0;
    HMODULE         hMod			= GetModuleHandleA("kernel32.dll");
	BYTE			pPreFuncCode[8] = {0, };

	dwDataCount = 4;
	dwFuncSize = (DWORD)IC_RestorePrivilege - (DWORD)IC_SetDebugPrivilege;
    dwSize = dwFuncSize + dwDataCount*sizeof(PVOID) + 4*sizeof(PVOID);

    if( !(pAllocated = (DWORD*)VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE)) )
		return NULL;

	TRACE("InjectCode_SetDebugPrivilege # Allocated address : 0x%08X\n", (DWORD)pAllocated);

	GetCallCode(pPreFuncCode, (DWORD)pAllocated);

	pPtr = pAllocated;

	if( !WriteProcessMemory(hProcess, pPtr++, &pPreFuncCode, sizeof(pPreFuncCode), NULL) )
        return NULL;

	pPtr++;
	
	hMod = GetModuleHandleA("Advapi32.dll");

	dwData = (DWORD)GetProcAddress(hMod, "OpenProcessToken");

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	hMod = GetModuleHandleA("kernel32.dll");

	dwData = (DWORD)GetProcAddress(hMod, "GetCurrentProcess");

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	hMod = GetModuleHandleA("Advapi32.dll");

	dwData = (DWORD)GetProcAddress(hMod, "LookupPrivilegeValueA");

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	dwData = (DWORD)GetProcAddress(hMod, "AdjustTokenPrivileges");

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	dwData = (DWORD)AllocStringVar(hProcess, SE_DEBUG_NAME);

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	dwData = BOUNDARY_MARK;

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	if( !WriteProcessMemory(hProcess, pPtr, IC_SetDebugPrivilege, dwFuncSize, NULL) )
        return NULL;

	return pAllocated;
}

LPVOID InjectCode_RestorePrivilege(HANDLE hProcess)
{
	DWORD			*pAllocated		= NULL;
	DWORD			*pPtr			= NULL;
	DWORD			dwSize			= 0;
	DWORD			dwData			= 0;
	DWORD			dwDataCount		= 0;
	DWORD			dwFuncSize		= 0;
    HMODULE         hMod			= GetModuleHandleA("Advapi32.dll");
	BYTE			pPreFuncCode[8] = {0, };

	dwDataCount = 1;
	dwFuncSize = (DWORD)IC_GetOSVersion - (DWORD)IC_RestorePrivilege;
    dwSize = dwFuncSize + dwDataCount*sizeof(PVOID) + 4*sizeof(PVOID);

    if( !(pAllocated = (DWORD*)VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE)) )
		return NULL;

	TRACE("InjectCode_RestorePrivilege # Allocated address : 0x%08X\n", (DWORD)pAllocated);

	GetCallCode(pPreFuncCode, (DWORD)pAllocated);

	pPtr = pAllocated;

	if( !WriteProcessMemory(hProcess, pPtr++, &pPreFuncCode, sizeof(pPreFuncCode), NULL) )
        return NULL;

	pPtr++;
	
	dwData = (DWORD)GetProcAddress(hMod, "AdjustTokenPrivileges");

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	dwData = BOUNDARY_MARK;

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	if( !WriteProcessMemory(hProcess, pPtr, IC_RestorePrivilege, dwFuncSize, NULL) )
        return NULL;

	return pAllocated;
}

LPVOID InjectCode_GetOSVersion(HANDLE hProcess)
{
	DWORD			*pAllocated		= NULL;
	DWORD			*pPtr			= NULL;
	DWORD			dwSize			= 0;
	DWORD			dwData			= 0;
	DWORD			dwDataCount		= 0;
	DWORD			dwFuncSize		= 0;
    HMODULE         hMod			= NULL;
	BYTE			pPreFuncCode[8] = {0, };

	hMod			= GetModuleHandleA("kernel32.dll");

	dwDataCount = 2;
	dwFuncSize = (DWORD)IC_MyPreFunction - (DWORD)IC_GetOSVersion;
    dwSize = dwFuncSize + dwDataCount*sizeof(PVOID) + 4*sizeof(PVOID);

    if( !(pAllocated = (DWORD*)VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE)) )
		return NULL;

	TRACE("InjectCode_GetOSVersion # Allocated address : 0x%08X\n", (DWORD)pAllocated);

	GetCallCode(pPreFuncCode, (DWORD)pAllocated);

	pPtr = pAllocated;

	if( !WriteProcessMemory(hProcess, pPtr++, &pPreFuncCode, sizeof(pPreFuncCode), NULL) )
        return NULL;

	pPtr++;
	
	dwData = (DWORD)GetProcAddress(hMod, "GetVersionExA");

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	hMod = GetModuleHandleA("ntdll.dll");

	dwData = (DWORD)GetProcAddress(hMod, "memset");

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	dwData = BOUNDARY_MARK;

	if( !WriteProcessMemory(hProcess, pPtr++, &dwData, sizeof(dwData), NULL) )
        return NULL;

	if( !WriteProcessMemory(hProcess, pPtr, IC_GetOSVersion, dwFuncSize, NULL) )
        return NULL;

	return pAllocated;
}

LPVOID InjectCode_ThreadProc(HANDLE hProcess)
{
	DWORD			*pAllocated		= NULL;
	DWORD			*pPtr			= NULL;
	DWORD			dwSize			= 0;
	DWORD			dwData			= 0;
	DWORD			dwDataCount		= 0;
	DWORD			dwFuncSize		= 0;
    HMODULE         hMod			= GetModuleHandleA("kernel32.dll");
	BYTE			pPreFuncCode[8] = {0, };

	dwFuncSize = (DWORD)IC_EjectThreadProc - (DWORD)IC_ThreadProc;

    if( !(pAllocated = (DWORD*)VirtualAllocEx(hProcess, NULL, dwFuncSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE)) )
		return NULL;

	TRACE("InjectCode_ThreadProc # Allocated address : 0x%08X\n", (DWORD)pAllocated);

	if( !WriteProcessMemory(hProcess, pAllocated, IC_ThreadProc, dwFuncSize, NULL) )
        return NULL;

	return pAllocated;
}

LPVOID InjectCode_EjectThreadProc(HANDLE hProcess)
{
	DWORD			*pAllocated		= NULL;
	DWORD			*pPtr			= NULL;
	DWORD			dwSize			= 0;
	DWORD			dwData			= 0;
	DWORD			dwDataCount		= 0;
	DWORD			dwFuncSize		= 0;
    HMODULE         hMod			= GetModuleHandleA("kernel32.dll");
	BYTE			pPreFuncCode[8] = {0, };

	dwFuncSize = (DWORD)IC_HookAPI - (DWORD)IC_EjectThreadProc;

    if( !(pAllocated = (DWORD*)VirtualAllocEx(hProcess, NULL, dwFuncSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE)) )
		return NULL;

	TRACE("InjectCode_EjectThreadProc # Allocated address : 0x%08X\n", (DWORD)pAllocated);

	if( !WriteProcessMemory(hProcess, pAllocated, IC_EjectThreadProc, dwFuncSize, NULL) )
        return NULL;

	return pAllocated;
}

LPVOID PrepareInjectThreadParam(HANDLE hProcess, LPVOID fCallFunc, LPVOID fNewFunc, PBYTE pOrgBytes)
{
	DWORD			*pAllocated		= NULL;
	DWORD			*pPtr			= NULL;
	DWORD			dwSize			= 0;
	DWORD			dwData			= 0;
	DWORD			dwDataCount		= 0;
	DWORD			dwFuncSize		= 0;
    HMODULE         hMod			= GetModuleHandleA("ntdll.dll");
	BYTE			pPreFuncCode[8] = {0, };

	THREAD_PARAM stParam = {0, };

	stParam.dwAddrOfTargetFunc = (DWORD)GetProcAddress(hMod, "ZwResumeThread");
	stParam.fCallFunc = fCallFunc;
	stParam.fNewFunc = fNewFunc;
	stParam.pOrgBytes = pOrgBytes;
	stParam.fLoadLibraryA = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
	stParam.szLib = (char*)pOrgBytes + 20;

    if( !(pAllocated = (DWORD*)VirtualAllocEx(hProcess, NULL, sizeof(THREAD_PARAM), MEM_COMMIT, PAGE_EXECUTE_READWRITE)) )
		return NULL;

	TRACE("ThreadParam # Allocated address : 0x%08X\n", (DWORD)pAllocated);

	if( !WriteProcessMemory(hProcess, pAllocated, (LPVOID)&stParam, sizeof(THREAD_PARAM), NULL) )
        return NULL;

	return pAllocated;
}

LPVOID PrepareEjectThreadParam(HANDLE hProcess, LPVOID pInjectedThreadParam, LPVOID fCallFunc)
{
	if( !WriteProcessMemory(hProcess, (LPVOID)((char*)pInjectedThreadParam + 12), (LPVOID)&fCallFunc, sizeof(LPVOID), NULL) )
        return NULL;

	return pInjectedThreadParam;
}

BYTE* GetCallCode(BYTE *pCallCode, DWORD dwAddr)
{
	DWORD dwBuf = g_dwPreFuncAddr - dwAddr - 5;

	pCallCode[0] = 0xE8;
	memcpy(&(pCallCode[1]), &dwBuf, sizeof(dwBuf));

	return pCallCode;
}

