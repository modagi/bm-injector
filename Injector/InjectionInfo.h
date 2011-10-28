/************************************************************************
    This file is part of BM Injector.

	FILE : InjectionInfo.h
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

class CInjectionInfo
{
public:
	CInjectionInfo();
	virtual ~CInjectionInfo();

	void Initialize();

	void SetDLLPath(CString strDLLPath);
	BOOL SetAddrGlobalVar(LPVOID pAddr);
	BOOL SetAddrPreFunc(LPVOID pAddr);
	BOOL SetAddrHookAPI(LPVOID pAddr);
	BOOL SetAddrUnhookAPI(LPVOID pAddr);
	BOOL SetAddrGetOSVersion(LPVOID pAddr);
	BOOL SetAddrSetDebugPrivilege(LPVOID pAddr);
	BOOL SetAddrRestorePrivilege(LPVOID pAddr);
	BOOL SetAddrInjectDll(LPVOID pAddr);
	BOOL SetAddrMyZwResumeThread(LPVOID pAddr);
	BOOL SetAddrThreadProc(LPVOID pAddr);
	BOOL SetAddrEjectThreadProc(LPVOID pAddr);
	BOOL SetAddrThreadParam(LPVOID pAddr);


	GLOBAL_VAR * GetAddrGlobalVar()		{ return m_pGlobalVar; };
	LPVOID GetAddrPreFunc()				{ return m_pAddrPreFunc; };
	LPVOID GetAddrHookAPI()				{ return m_pAddrHookAPI; };
	LPVOID GetAddrUnhookAPI()			{ return m_pAddrUnhookAPI; };
	LPVOID GetAddrGetOSVersion()		{ return m_pAddrGetOSVersion; };
	LPVOID GetAddrSetDebugPrivilege()	{ return m_pAddrSetDebugPrivilege; };
	LPVOID GetAddrRestorePrivilege()	{ return m_pAddrRestorePrivilege; };
	LPVOID GetAddrInjectDll()			{ return m_pAddrInjectDll; };
	LPVOID GetAddrMyZwResumeThread()	{ return m_pAddrMyZwResumeThread; };
	LPVOID GetAddrThreadProc()			{ return m_pAddrThreadProc; };
	LPVOID GetAddrEjectThreadProc()		{ return m_pAddrEjectThreadProc; };
	LPVOID GetAddrThreadParam()			{ return m_pAddrThreadParam; };

	BOOL Release(HANDLE hProcess);
	BOOL ReleaseVar(LPVOID &pVar);
	BOOL ReleaseGlobalVar();
protected:
	HANDLE m_hProcess;
	CString m_strDLLPath;

	GLOBAL_VAR *m_pGlobalVar;
	LPVOID m_pAddrPreFunc;
	LPVOID m_pAddrHookAPI;
	LPVOID m_pAddrUnhookAPI;
	LPVOID m_pAddrGetOSVersion;
	LPVOID m_pAddrSetDebugPrivilege;
	LPVOID m_pAddrRestorePrivilege;
	LPVOID m_pAddrInjectDll;
	LPVOID m_pAddrMyZwResumeThread;
	LPVOID m_pAddrThreadProc;
	LPVOID m_pAddrEjectThreadProc;
	LPVOID m_pAddrThreadParam;
};