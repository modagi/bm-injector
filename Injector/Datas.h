/************************************************************************
    This file is part of BM Injector.

	FILE : Datas.h
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

#pragma once



typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID;

typedef struct _THREAD_BASIC_INFORMATION {
	DWORD ExitStatus;
	PVOID TebBaseAddress;
	CLIENT_ID ClientId;
	ULONG AffinityMask;
	LONG Priority;
	LONG BasePriority;
} THREAD_BASIC_INFORMATION;

typedef HMODULE (WINAPI *t_fLoadLibrary)
(
    LPCSTR lpLibFileName
);

typedef FARPROC (WINAPI *t_fGetProcAddress)
(
    HMODULE hModule,
    LPCSTR	lpProcName
);

typedef DWORD (WINAPI *t_fZwQueryInformationThread)
(
    HANDLE ThreadHandle, 
    ULONG ThreadInformationClass, 
    PVOID ThreadInformation, 
    ULONG ThreadInformationLength, 
    PULONG ReturnLength
);

typedef DWORD (WINAPI *t_fNtCreateThreadEx)
(
	PHANDLE                 ThreadHandle,	
    ACCESS_MASK             DesiredAccess,	
    LPVOID                  ObjectAttributes,	
    HANDLE                  ProcessHandle,	
    LPTHREAD_START_ROUTINE  lpStartAddress,	
    LPVOID                  lpParameter,	
    BOOL	                CreateSuspended,	
    DWORD                   dwStackSize,	
    DWORD                   dw1, 
    DWORD                   dw2, 
    LPVOID                  Unknown 
);

typedef NTSTATUS (WINAPI *t_fZwResumeThread)
(
    HANDLE hThread,
    PULONG SuspendCount
);

typedef HMODULE (WINAPI *t_fGetModuleHandle)(
	LPCTSTR lpModuleName
);

typedef BOOL (WINAPI *t_fVirtualProtect)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD flNewProtect,
	PDWORD lpflOldProtect
);

typedef DWORD (WINAPI *t_fGetCurrentProcessId)(void);

typedef HANDLE (WINAPI *t_fOpenProcess)(
	DWORD dwDesiredAccess,
	BOOL bInheritHandle,
	DWORD dwProcessId
);

typedef LPVOID (WINAPI *t_fVirtualAllocEx)(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD flAllocationType,
	DWORD flProtect
);

typedef BOOL (WINAPI *t_fWriteProcessMemory)(
	HANDLE hProcess,
	LPVOID lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T nSize,
	SIZE_T *lpNumberOfBytesWritten
);

typedef HANDLE (WINAPI *t_fCreateRemoteThread)(
	HANDLE hProcess,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	SIZE_T dwStackSize,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID lpParameter,
	DWORD dwCreationFlags,
	LPDWORD lpThreadId
);

typedef DWORD (WINAPI *t_fWaitForSingleObject)(
	HANDLE hHandle,
	DWORD dwMilliseconds
);

typedef BOOL (WINAPI *t_fVirtualFreeEx)(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD dwFreeType
);

typedef BOOL (WINAPI *t_fCloseHandle)(
	HANDLE hObject
);

typedef BOOL (WINAPI *t_fOpenProcessToken)(
	HANDLE ProcessHandle,
	DWORD DesiredAccess,
	PHANDLE TokenHandle
);

typedef HANDLE (WINAPI *t_fGetCurrentProcess)(void);

typedef BOOL (WINAPI *t_fLookUpPrivilegeValue)(
	LPCTSTR lpSystemName,
	LPCTSTR lpName,
	PLUID lpLuid
);

typedef BOOL (WINAPI *t_fAdjustTokenPrivilege)(
	HANDLE TokenHandle,
	BOOL DisableAllPrivileges,
	PTOKEN_PRIVILEGES NewState,
	DWORD BufferLength,
	PTOKEN_PRIVILEGES PreviousState,
	PDWORD ReturnLength
);

typedef BOOL (WINAPI *t_fGetVersionEx)(
	LPOSVERSIONINFO lpVersionInfo
);

typedef BOOL (WINAPI *t_fAdjustTokenPrivilegeS)(
	HANDLE TokenHandle,
	BOOL DisableAllPrivileges,
	PTOKEN_PRIVILEGES NewState,
	DWORD BufferLength,
	PTOKEN_PRIVILEGES PreviousState,
	PDWORD ReturnLength
);

typedef void *(_cdecl *t_fmemcpy)(
	void *_Dst,
	void *_Src,
	size_t _Size
);

typedef void *(__cdecl *t_fmemset)( //__cdecl
	void * _Dst,
	int _Val,
	size_t _Size
);

typedef int (WINAPI *t_fstrlenA)(
	LPCSTR lpString
);

typedef struct _THREAD_PARAM
{
	PBYTE pOrgBytes;
	DWORD dwAddrOfTargetFunc;
	LPVOID fNewFunc;
	LPVOID fCallFunc;
	char* szLib;
	LPVOID fLoadLibraryA;
} THREAD_PARAM, *PTHREAD_PARAM;

typedef struct _GLOBAL_VAR
{
    BYTE *pOrgCode;
	char *szNtdll;
	char *szNtCreateThreadEx;
	char *szKernel32;
	char *szLoadLibraryA;
	char *szLibAdvApi32;
} GLOBAL_VAR, *PGLOBAL_VAR;