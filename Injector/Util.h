/************************************************************************
    This file is part of BM Injector.

	FILE : Util.h
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

#include "InjectionInfo.h"
#include "Datas.h"

int GetOSVersion(BOOL bMajor = TRUE);
BOOL InjectDll(DWORD dwPid, LPCTSTR szDllName);
BOOL EjectDll(DWORD dwPID, LPCTSTR szDllName);
BOOL InjectCode(DWORD dwPID, LPCTSTR szDllPath, CInjectionInfo &info);
BOOL EjectCode(DWORD dwPID, CInjectionInfo &info);
BOOL SetDebugPrivilege(HANDLE *phProcessToken, TOKEN_PRIVILEGES *pOldToken, DWORD *pdwOldCount);
BOOL RestorePrivilege(HANDLE hProcessToken, TOKEN_PRIVILEGES stOldToken, DWORD dwOldCount);

void ErrorMessageBox(LPCTSTR lpszErrCaption);

LPVOID AllocGlobalVars(HANDLE hProcess);
LPVOID AllocStringVar(HANDLE hProcess, LPCTSTR szStr);
LPVOID InjectCode_MyPreFunction(HANDLE hProcess);
LPVOID InjectCode_HookAPI(HANDLE hProcess);
LPVOID InjectCode_UnhookAPI(HANDLE hProcess);
LPVOID InjectCode_MyZwResumeThread(HANDLE hProcess, LPCTSTR szDllPath, GLOBAL_VAR *pstGlobalVar, LPVOID pAddrHookAPI, LPVOID pAddrUnhookAPI, LPVOID pAddrInjectDll);
LPVOID InjectCode_InjectDll(HANDLE hProcess, LPVOID pAddrGetOSVersion, LPVOID pAddrSetDebugPrivilege, LPVOID pAddrRestorePrivilege);
LPVOID InjectCode_SetDebugPrivilege(HANDLE hProcess);
LPVOID InjectCode_RestorePrivilege(HANDLE hProcess);
LPVOID InjectCode_GetOSVersion(HANDLE hProcess);
LPVOID InjectCode_ThreadProc(HANDLE hProcess);
LPVOID InjectCode_EjectThreadProc(HANDLE hProcess);
LPVOID PrepareInjectThreadParam(HANDLE hProcess, LPVOID fCallFunc, LPVOID fNewFunc, PBYTE pOrgBytes);
LPVOID PrepareEjectThreadParam(HANDLE hProcess, LPVOID pInjectedThreadParam, LPVOID fCallFunc);

BYTE* GetCallCode(BYTE *pCallCode, DWORD dwAddr);