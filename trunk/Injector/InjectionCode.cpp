/************************************************************************
    This file is part of BM Injector.

	FILE : InjectionCode.cpp
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

#include "stdafx.h"

#include "InjectionCode.h"

BYTE g_pOrgZwResumeThreadCode[5] = {0,};

DWORD WINAPI IC_ThreadProc(LPVOID lParam)
{
	PTHREAD_PARAM pParam = (PTHREAD_PARAM)lParam;
	PFIC_HOOKAPI fHookAPI = (PFIC_HOOKAPI)pParam->fCallFunc;
	t_fLoadLibrary fLoadLibraryA = (t_fLoadLibrary)pParam->fLoadLibraryA;
	char **ppLib = (char**)pParam->szLib;

	fLoadLibraryA((LPCSTR)*ppLib);

	fHookAPI((FARPROC)pParam->dwAddrOfTargetFunc, (PROC)pParam->fNewFunc, pParam->pOrgBytes);
	
    return 0;
}

DWORD WINAPI IC_EjectThreadProc(LPVOID lParam)
{
	PTHREAD_PARAM pParam = (PTHREAD_PARAM)lParam;
	PFIC_UNHOOKAPI fUnhookAPI = (PFIC_UNHOOKAPI)pParam->fCallFunc;

	fUnhookAPI((FARPROC)pParam->dwAddrOfTargetFunc, pParam->pOrgBytes);

	return 0;
}

// GetModuleHandle
// GetProcAddress
// VirtualProtect
// memcpy
BOOL WINAPI IC_HookAPI(FARPROC pFunc, PROC pfNew, PBYTE pOrgBytes)
{
	DWORD	dwOldProtect = 0, dwAddress = 0;
	BYTE	pBuf[5];
	PBYTE	pByte = NULL;

	t_fmemcpy fmemcpy = NULL;
	t_fVirtualProtect fVirtualProtect = NULL;
	t_fGetProcAddress fGetProcAddress = NULL;
	t_fGetModuleHandle fGetModuleHandle = NULL;
	
	DWORD *pFuncPtr = NULL;

	_asm	MOV		pFuncPtr, EAX

	pFuncPtr -= 2;
	fmemcpy = (t_fmemcpy)*pFuncPtr;

	pFuncPtr--;
	fVirtualProtect = (t_fVirtualProtect)*pFuncPtr;

	pFuncPtr--;
	fGetProcAddress = (t_fGetProcAddress)*pFuncPtr;

	pFuncPtr--;
	fGetModuleHandle = (t_fGetModuleHandle)*pFuncPtr;

	pByte = (PBYTE)pFunc;

	if( !fVirtualProtect((LPVOID)pFunc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect) )
    {
        return FALSE;
    }

	pBuf[0] = 0xE9;
	fmemcpy(pOrgBytes, pFunc, 5);

	dwAddress = (DWORD)pfNew - (DWORD)pFunc - 5;
	fmemcpy(&pBuf[1], &dwAddress, 4);

	fmemcpy(pFunc, pBuf, 5);

	if( !fVirtualProtect((LPVOID)pFunc, 5, dwOldProtect, &dwOldProtect) )
    {
        return FALSE;
    }

	return TRUE;
}

// GetModuleHandle
// GetProcAddress
// VirtualProtect
// memcpy
BOOL WINAPI IC_UnhookAPI(FARPROC pFunc, PBYTE pOrgBytes)
{
	DWORD dwOldProtect = 0;
	PBYTE pByte = NULL;
    HMODULE hMod = NULL;

	t_fmemcpy fmemcpy = NULL;
	t_fVirtualProtect fVirtualProtect = NULL;
	t_fGetProcAddress fGetProcAddress = NULL;
	t_fGetModuleHandle fGetModuleHandle = NULL;

	DWORD *pFuncPtr = NULL;

	_asm	MOV	pFuncPtr, EAX
	
	pFuncPtr -= 2;
	fmemcpy = (t_fmemcpy)*pFuncPtr;

	pFuncPtr--;
	fVirtualProtect = (t_fVirtualProtect)*pFuncPtr;

	pFuncPtr--;
	fGetProcAddress = (t_fGetProcAddress)*pFuncPtr;

	pFuncPtr--;
	fGetModuleHandle = (t_fGetModuleHandle)*pFuncPtr;

	pByte = (PBYTE)pFunc;

	if( !fVirtualProtect((LPVOID)pFunc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect) )
    {
        return FALSE;
    }

	fmemcpy(pFunc, pOrgBytes, 5);

	if( !fVirtualProtect((LPVOID)pFunc, 5, dwOldProtect, &dwOldProtect) )
    {
        return FALSE;
    }

	return TRUE;
}

// dwPrevPID
// [DLL path for injection]
// g_pOrgZwResumeThreadCode
// GetCurrentProcessId
// ZwQueryInformationThread
// ZwResumeThread
// IC_InjectDll
// IC_UnhookAPI
// IC_HookAPI
// IC_MyZwResumeThread
NTSTATUS WINAPI IC_MyZwResumeThread(HANDLE hThread, PULONG SuspendCount)
{
    NTSTATUS	status, statusThread;
    FARPROC		pFuncThread = NULL;
    DWORD		dwPID = 0;
    HMODULE hMod = NULL;
	FARPROC pFuncThreadInfo = NULL;
	THREAD_BASIC_INFORMATION tbi;

	char *pDllPath = NULL;
	t_fZwResumeThread fIC_MyZwResumeThread = NULL;
	PFIC_HOOKAPI fIC_HookAPI = NULL;
	PFIC_UNHOOKAPI fIC_UnhookAPI = NULL;
	PFIC_INJECTDLL fIC_InjectDll = NULL;
	t_fZwResumeThread fZwResumeThread = NULL;
	t_fZwQueryInformationThread fZwQueryInformationThread = NULL;
	t_fGetCurrentProcessId fGetCurrentProcessId = NULL;
	BYTE *pOrgZwResumeThreadCode = NULL;
	DWORD *pdwPrevPID = NULL;

	DWORD *pFuncPtr = NULL;

	_asm	MOV	pFuncPtr, EAX	

	pFuncPtr -= 2;
	fIC_MyZwResumeThread = (t_fZwResumeThread)*pFuncPtr;

	pFuncPtr--;
	fIC_HookAPI = (PFIC_HOOKAPI)*pFuncPtr;

	pFuncPtr--;
	fIC_UnhookAPI = (PFIC_UNHOOKAPI)*pFuncPtr;

	pFuncPtr--;
	fIC_InjectDll = (PFIC_INJECTDLL)*pFuncPtr;

	pFuncPtr--;
	fZwResumeThread = (t_fZwResumeThread)*pFuncPtr;

	pFuncPtr--;
	fZwQueryInformationThread = (t_fZwQueryInformationThread)*pFuncPtr;

	pFuncPtr--;
	fGetCurrentProcessId = (t_fGetCurrentProcessId)*pFuncPtr;

	pFuncPtr--;
	pOrgZwResumeThreadCode = (BYTE*)*pFuncPtr;

	pFuncPtr--;
	pDllPath = (char*)*pFuncPtr;

	pFuncPtr--;
	pdwPrevPID = (DWORD*)pFuncPtr;

//	hMod = GetModuleHandle("ntdll.dll");
//	pFuncThreadInfo = GetProcAddress(hMod, "ZwQueryInformationThread");
	statusThread = fZwQueryInformationThread(hThread, 0, &tbi, sizeof(tbi), NULL);

    if( !fIC_UnhookAPI((FARPROC)fZwResumeThread, pOrgZwResumeThreadCode) )
    {
        return NULL;
    }

	status = fZwResumeThread(hThread, SuspendCount);

	dwPID = (DWORD)tbi.ClientId.UniqueProcess;
	if ( dwPID != fGetCurrentProcessId() && dwPID != *pdwPrevPID )
	{
		*pdwPrevPID = dwPID;
		fIC_InjectDll(dwPID, pDllPath);
	}

	if( status != STATUS_SUCCESS )
    {
        if ( !fIC_HookAPI((FARPROC)fZwResumeThread, (PROC)fIC_MyZwResumeThread, pOrgZwResumeThreadCode) )
			return NULL;

		return status;
    }

    if( !fIC_HookAPI((FARPROC)fZwResumeThread, (PROC)fIC_MyZwResumeThread, pOrgZwResumeThreadCode) )
    {
    }
	
    return status;
}

// OpenProcess
// VirtualAllocEx
// WriteProcessMemory
// CreateRemoteThread
// LoadLibraryA
// WaitForSingleObject
// VirtualFreeEx
// CloseHandle
// lstrlenA
// NtCreateThreadEx		ntdll.dll
// IC_GetOSVersion
// IC_RestorePrivilege
// IC_SetDebugPrivilege
BOOL WINAPI IC_InjectDll(DWORD dwPid, LPCTSTR szDllName)
{
	HANDLE					hProcess, hMod, hThread;
	LPVOID					pRemoteBuf;
	DWORD					dwBufSize = 0;

	HANDLE					hProcessToken	= NULL;
	TOKEN_PRIVILEGES		stOldToken;
	DWORD					dwOldCount		= 0;

	PFIC_SETDEBUGPRIVILEGE	fIC_SetDebugPrivilege	= NULL;
	PFIC_RESTOREPRIVILEGE	fIC_RestorePrivilege	= NULL;
	PFIC_GETOSVERSION		fIC_GetOSVersion		= NULL;
	t_fNtCreateThreadEx		fNtCreateThreadEx		= NULL;
	t_fstrlenA				flstrlenA				= NULL;
	t_fCloseHandle			fCloseHandle			= NULL;
	t_fVirtualFreeEx		fVirtualFreeEx			= NULL;
	t_fWaitForSingleObject	fWaitForSingleObject	= NULL;
	t_fLoadLibrary			fLoadLibraryA			= NULL;
	t_fCreateRemoteThread	fCreateRemoteThread		= NULL;
	t_fWriteProcessMemory	fWriteProcessMemory		= NULL;
	t_fVirtualAllocEx		fVirtualAllocEx			= NULL;
	t_fOpenProcess			fOpenProcess			= NULL;

	DWORD *pFuncPtr = NULL;

	_asm	MOV	pFuncPtr, EAX
	
	pFuncPtr -= 2;
	fOpenProcess = (t_fOpenProcess)*pFuncPtr;

	pFuncPtr--;
	fVirtualAllocEx = (t_fVirtualAllocEx)*pFuncPtr;

	pFuncPtr--;
	fWriteProcessMemory = (t_fWriteProcessMemory)*pFuncPtr;

	pFuncPtr--;
	fCreateRemoteThread = (t_fCreateRemoteThread)*pFuncPtr;

	pFuncPtr--;
	fLoadLibraryA = (t_fLoadLibrary)*pFuncPtr;

	pFuncPtr--;
	fWaitForSingleObject = (t_fWaitForSingleObject)*pFuncPtr;

	pFuncPtr--;
	fVirtualFreeEx = (t_fVirtualFreeEx)*pFuncPtr;

	pFuncPtr--;
	fCloseHandle = (t_fCloseHandle)*pFuncPtr;

	pFuncPtr--;
	flstrlenA = (t_fstrlenA)*pFuncPtr;

	pFuncPtr--;
	fNtCreateThreadEx = (t_fNtCreateThreadEx)*pFuncPtr;

	pFuncPtr--;
	fIC_GetOSVersion = (PFIC_GETOSVERSION)*pFuncPtr;

	pFuncPtr--;
	fIC_RestorePrivilege = (PFIC_RESTOREPRIVILEGE)*pFuncPtr;

	pFuncPtr--;
	fIC_SetDebugPrivilege = (PFIC_SETDEBUGPRIVILEGE)*pFuncPtr;

	dwBufSize = flstrlenA(szDllName)+1;

	if ( !fIC_SetDebugPrivilege(&hProcessToken, &stOldToken, &dwOldCount) )
		return FALSE;

	if ( !(hProcess = fOpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid)) )
	{
		fIC_RestorePrivilege(hProcessToken, stOldToken, dwOldCount);
		return FALSE;
	}

	if ( !fIC_RestorePrivilege(hProcessToken, stOldToken, dwOldCount) )
		return FALSE;
	
	if ( !(pRemoteBuf = fVirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE)) )
		return FALSE;

	if ( !fWriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllName, dwBufSize, NULL) )
		return FALSE;

	if ( fIC_GetOSVersion(TRUE) < 6 )
	{
		if ( !(hThread = fCreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)fLoadLibraryA, pRemoteBuf, 0, NULL)) )
			return FALSE;
	}
	else
	{
		fNtCreateThreadEx(&hThread,
			0x1FFFFF,
			NULL,
			hProcess,
			(LPTHREAD_START_ROUTINE)fLoadLibraryA,
			pRemoteBuf,
			FALSE,
			NULL,
			NULL,
			NULL,
			NULL);

		if ( hThread == NULL)
			return FALSE;
	}

	if ( fWaitForSingleObject(hThread, INFINITE) )
		return FALSE;

	fVirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);

	fCloseHandle(hProcess);

	return TRUE;
}

// OpenProcessToken
// GetCurrentProcess
// LookupPrivilegeValue
// AdjustTokenPrivileges
// SE_DEBUG_NAME "SeDebugPrivilege"
BOOL WINAPI IC_SetDebugPrivilege(HANDLE *phProcessToken, TOKEN_PRIVILEGES *pOldToken, DWORD *pdwOldCount)
{
	TOKEN_PRIVILEGES stNewToken;

	char *pSeDebugPrivilege = NULL;
	t_fAdjustTokenPrivilegeS fAdjustTokenPrivileges = NULL;
	t_fLookUpPrivilegeValue fLookupPrivilegeValue = NULL;
	t_fGetCurrentProcess fGetCurrentProcess = NULL;
	t_fOpenProcessToken fOpenProcessToken = NULL;

	DWORD *pFuncPtr = NULL;

	_asm	MOV	pFuncPtr, EAX
	
	pFuncPtr -= 2;
	pSeDebugPrivilege = (char*)*pFuncPtr;

	pFuncPtr--;
	fAdjustTokenPrivileges = (t_fAdjustTokenPrivilegeS)*pFuncPtr;

	pFuncPtr--;
	fLookupPrivilegeValue = (t_fLookUpPrivilegeValue)*pFuncPtr;

	pFuncPtr--;
	fGetCurrentProcess = (t_fGetCurrentProcess)*pFuncPtr;

	pFuncPtr--;
	fOpenProcessToken = (t_fOpenProcessToken)*pFuncPtr;

	if ( !fOpenProcessToken(fGetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, phProcessToken) )
	{
		return FALSE;
	}

	if ( !fLookupPrivilegeValue(NULL, pSeDebugPrivilege, &(stNewToken.Privileges[0].Luid)) )
	{
		return FALSE;
	}

	stNewToken.PrivilegeCount = 1;
	stNewToken.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if ( !fAdjustTokenPrivileges(*phProcessToken, FALSE, &stNewToken, sizeof(TOKEN_PRIVILEGES), pOldToken, pdwOldCount) )
	{
		return FALSE;
	}

	return TRUE;
}

// AdjustTokenPrivileges
BOOL WINAPI IC_RestorePrivilege(HANDLE hProcessToken, TOKEN_PRIVILEGES stOldToken, DWORD dwOldCount)
{
	t_fAdjustTokenPrivilegeS fAdjustTokenPrivileges = NULL;

	DWORD *pFuncPtr = NULL;

	_asm	MOV	pFuncPtr, EAX
	

	pFuncPtr -= 2;
	fAdjustTokenPrivileges = (t_fAdjustTokenPrivilegeS)*pFuncPtr;

	if ( !fAdjustTokenPrivileges(hProcessToken, FALSE, &stOldToken, dwOldCount, NULL, NULL) )
	{
		return FALSE;
	}

	return TRUE;
}

// GetVersionEx
// memset
int WINAPI IC_GetOSVersion(BOOL bMajor)
{
	t_fGetVersionEx fGetVersionEx = NULL;
	t_fmemset fmemset = NULL;

	DWORD *pFuncPtr = NULL;

	_asm	MOV	pFuncPtr, EAX
	
	pFuncPtr -= 2;
	fmemset = (t_fmemset)*pFuncPtr;

	pFuncPtr--;
	fGetVersionEx = (t_fGetVersionEx)*pFuncPtr;

	OSVERSIONINFO osver;

	fmemset(&osver, 0, sizeof(osver));

	osver.dwOSVersionInfoSize = sizeof(osver);

	fGetVersionEx(&osver);

	return osver.dwMajorVersion; 
}

void __declspec(naked) IC_MyPreFunction()
{
	_asm
	{
		POP		EAX
		SUB		EAX, 1
LOOP_FIND_MARK:
		ADD		EAX, 4
		CMP		DWORD PTR[EAX], BOUNDARY_MARK
		JNE		LOOP_FIND_MARK
		ADD		EAX, 4
		JMP		EAX
	}
}

void IC_Boundary()
{
}