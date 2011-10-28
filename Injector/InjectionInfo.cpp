/************************************************************************
    This file is part of BM Injector.

	FILE : InjectionInfo.cpp
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
#include "InjectionInfo.h"

CInjectionInfo::CInjectionInfo()
{
	m_hProcess = NULL;
	m_strDLLPath = "";

	m_pGlobalVar = NULL;
	m_pAddrPreFunc = NULL;
	m_pAddrHookAPI = NULL;
	m_pAddrUnhookAPI = NULL;
	m_pAddrGetOSVersion = NULL;
	m_pAddrSetDebugPrivilege = NULL;
	m_pAddrRestorePrivilege = NULL;
	m_pAddrInjectDll = NULL;
	m_pAddrMyZwResumeThread = NULL;
	m_pAddrThreadProc = NULL;
	m_pAddrEjectThreadProc = NULL;
	m_pAddrThreadParam = NULL;
}

CInjectionInfo::~CInjectionInfo()
{
}

void CInjectionInfo::Initialize()
{
	m_hProcess = NULL;
	m_strDLLPath = "";

	m_pGlobalVar = NULL;
	m_pAddrPreFunc = NULL;
	m_pAddrHookAPI = NULL;
	m_pAddrUnhookAPI = NULL;
	m_pAddrGetOSVersion = NULL;
	m_pAddrSetDebugPrivilege = NULL;
	m_pAddrRestorePrivilege = NULL;
	m_pAddrInjectDll = NULL;
	m_pAddrMyZwResumeThread = NULL;
	m_pAddrThreadProc = NULL;
	m_pAddrEjectThreadProc = NULL;
	m_pAddrThreadParam = NULL;
}

void CInjectionInfo::SetDLLPath(CString strDLLPath)
{
	m_strDLLPath = strDLLPath;
}

BOOL CInjectionInfo::SetAddrGlobalVar(LPVOID pAddr)
{
	if ( pAddr == NULL )
		return FALSE;

	m_pGlobalVar = (GLOBAL_VAR*)pAddr;

	return TRUE;
}


BOOL CInjectionInfo::SetAddrPreFunc(LPVOID pAddr)
{
	if ( pAddr == NULL )
		return FALSE;

	m_pAddrPreFunc = pAddr;

	return TRUE;
}

BOOL CInjectionInfo::SetAddrHookAPI(LPVOID pAddr)
{
	if ( pAddr == NULL )
		return FALSE;

	m_pAddrHookAPI = pAddr;

	return TRUE;
}

BOOL CInjectionInfo::SetAddrUnhookAPI(LPVOID pAddr)
{
	if ( pAddr == NULL )
		return FALSE;

	m_pAddrUnhookAPI = pAddr;

	return TRUE;
}

BOOL CInjectionInfo::SetAddrGetOSVersion(LPVOID pAddr)
{
	if ( pAddr == NULL )
		return FALSE;

	m_pAddrGetOSVersion = pAddr;

	return TRUE;
}


BOOL CInjectionInfo::SetAddrSetDebugPrivilege(LPVOID pAddr)
{
	if ( pAddr == NULL )
		return FALSE;

	m_pAddrSetDebugPrivilege = pAddr;

	return TRUE;
}


BOOL CInjectionInfo::SetAddrRestorePrivilege(LPVOID pAddr)
{
	if ( pAddr == NULL )
		return FALSE;

	m_pAddrRestorePrivilege = pAddr;

	return TRUE;
}


BOOL CInjectionInfo::SetAddrInjectDll(LPVOID pAddr)
{
	if ( pAddr == NULL )
		return FALSE;

	m_pAddrInjectDll = pAddr;

	return TRUE;
}


BOOL CInjectionInfo::SetAddrMyZwResumeThread(LPVOID pAddr)
{
	if ( pAddr == NULL )
		return FALSE;

	m_pAddrMyZwResumeThread = pAddr;

	return TRUE;
}


BOOL CInjectionInfo::SetAddrThreadProc(LPVOID pAddr)
{
	if ( pAddr == NULL )
		return FALSE;

	m_pAddrThreadProc = pAddr;

	return TRUE;
}


BOOL CInjectionInfo::SetAddrEjectThreadProc(LPVOID pAddr)
{
	if ( pAddr == NULL )
		return FALSE;

	m_pAddrEjectThreadProc = pAddr;

	return TRUE;
}


BOOL CInjectionInfo::SetAddrThreadParam(LPVOID pAddr)
{
	if ( pAddr == NULL )
		return FALSE;

	m_pAddrThreadParam = pAddr;

	return TRUE;
}


BOOL CInjectionInfo::Release(HANDLE hProcess)
{
	BOOL bResult = TRUE;

	m_hProcess = hProcess;

	bResult = ReleaseVar(m_pAddrPreFunc) ? bResult : FALSE;
	bResult = ReleaseVar(m_pAddrHookAPI) ? bResult : FALSE;
	bResult = ReleaseVar(m_pAddrUnhookAPI) ? bResult : FALSE;
	bResult = ReleaseVar(m_pAddrGetOSVersion) ? bResult : FALSE;
	bResult = ReleaseVar(m_pAddrSetDebugPrivilege) ? bResult : FALSE;
	bResult = ReleaseVar(m_pAddrRestorePrivilege) ? bResult : FALSE;
	bResult = ReleaseVar(m_pAddrInjectDll) ? bResult : FALSE;
	bResult = ReleaseVar(m_pAddrMyZwResumeThread) ? bResult : FALSE;
	bResult = ReleaseVar(m_pAddrThreadProc) ? bResult : FALSE;
	bResult = ReleaseVar(m_pAddrEjectThreadProc) ? bResult : FALSE;
	bResult = ReleaseVar(m_pAddrThreadParam) ? bResult : FALSE;

	m_hProcess = NULL;

	return bResult;
}

BOOL CInjectionInfo::ReleaseVar(LPVOID &pVar)
{
	if ( !pVar )
		return TRUE;
	
	if ( !VirtualFreeEx(m_hProcess, pVar, 0, MEM_RELEASE) )
		return FALSE;

	pVar = NULL;
	
	return TRUE;
}

BOOL CInjectionInfo::ReleaseGlobalVar()
{
	if ( !m_pGlobalVar )
		return TRUE;

	if ( !VirtualFreeEx(m_hProcess, m_pGlobalVar->pOrgCode, 0, MEM_RELEASE) )
		return FALSE;

	if ( !VirtualFreeEx(m_hProcess, m_pGlobalVar->szKernel32, 0, MEM_RELEASE) )
		return FALSE;

	if ( !VirtualFreeEx(m_hProcess, m_pGlobalVar->szLoadLibraryA, 0, MEM_RELEASE) )
		return FALSE;

	if ( !VirtualFreeEx(m_hProcess, m_pGlobalVar->szNtCreateThreadEx, 0, MEM_RELEASE) )
		return FALSE;

	if ( !VirtualFreeEx(m_hProcess, m_pGlobalVar->szNtdll, 0, MEM_RELEASE) )
		return FALSE;

	if ( !VirtualFreeEx(m_hProcess, m_pGlobalVar, 0, MEM_RELEASE) )
		return FALSE;

	return TRUE;
}