/************************************************************************
    This file is part of BM Injector.

	FILE : InjectionCode.h
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

#include "Datas.h"

typedef DWORD (WINAPI *PFIC_THREADPROC)
(
	LPVOID lParam
);

typedef BOOL (WINAPI *PFIC_HOOKAPI)
(
	FARPROC pFunc, 
	PROC	pfNew, 
	PBYTE	pOrgBytes
);
typedef BOOL (WINAPI *PFIC_UNHOOKAPI)
(
	FARPROC pFunc, 
	PBYTE	pOrgBytes
);

typedef BOOL (WINAPI *PFIC_INJECTDLL)
(
	DWORD	dwPid, 
	LPCTSTR szDllName
);

typedef BOOL (WINAPI *PFIC_SETDEBUGPRIVILEGE)
(
	HANDLE				*phProcessToken, 
	TOKEN_PRIVILEGES	*pOldToken, 
	DWORD				*pdwOldCount
);

typedef BOOL (WINAPI *PFIC_RESTOREPRIVILEGE)
(
	HANDLE				hProcessToken,
	TOKEN_PRIVILEGES	stOldToken, 
	DWORD				dwOldCount
);

typedef int	(WINAPI *PFIC_GETOSVERSION)
(
	BOOL bMajor
);


DWORD		WINAPI	IC_ThreadProc(LPVOID lParam);
DWORD		WINAPI	IC_EjectThreadProc(LPVOID lParam);
BOOL		WINAPI	IC_HookAPI(FARPROC pFunc, PROC pfNew, PBYTE pOrgBytes);
BOOL		WINAPI	IC_UnhookAPI(FARPROC pFunc, PBYTE pOrgBytes);
NTSTATUS	WINAPI	IC_MyZwResumeThread(HANDLE hThread, PULONG SuspendCount);
BOOL		WINAPI	IC_InjectDll(DWORD dwPid, LPCTSTR szDllName);
BOOL		WINAPI	IC_SetDebugPrivilege(HANDLE *phProcessToken, TOKEN_PRIVILEGES *pOldToken, DWORD *pdwOldCount);
BOOL		WINAPI	IC_RestorePrivilege(HANDLE hProcessToken, TOKEN_PRIVILEGES stOldToken, DWORD dwOldCount);
int			WINAPI	IC_GetOSVersion(BOOL bMajor = TRUE);
void				IC_MyPreFunction();
void				IC_Boundary();
