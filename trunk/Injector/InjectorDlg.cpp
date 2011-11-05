/************************************************************************
    This file is part of BM Injector.

	FILE : InjectorDlg.cpp
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

// InjectorDlg.cpp : implementation file
//

#include "stdafx.h"
#include "Injector.h"
#include "InjectorDlg.h"
#include "Util.h"
#include "InjectionInfo.h"
#include "AboutDlg.h"

#include <vector>
#include <map>
#include <process.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <io.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

using namespace std;

// CInjectorDlg dialog




CInjectorDlg::CInjectorDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CInjectorDlg::IDD, pParent)
	, m_strDllPath("")
	, m_strLog(_T(""))
	, m_nLogLevel(0)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);

}

void CInjectorDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT_DLL, m_strDllPath);
	DDX_Control(pDX, IDC_BTN_GLOBAL, m_btnGlobal);
	DDX_Control(pDX, IDC_LIST_PROC, m_listProc);
	DDX_Control(pDX, IDC_LIST_RESULT, m_listDllResult);
	DDX_Control(pDX, IDC_LIST_CODE_RESULT, m_listCodeResult);
	DDX_Text(pDX, IDC_EDIT_LOG, m_strLog);
	DDX_Control(pDX, IDC_COMBO_LOGLEVEL, m_cboLogLevel);
	DDX_CBIndex(pDX, IDC_COMBO_LOGLEVEL, m_nLogLevel);
}

BEGIN_MESSAGE_MAP(CInjectorDlg, CDialog)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//}}AFX_MSG_MAP
	ON_BN_CLICKED(IDC_BTN_DLL, &CInjectorDlg::OnBnClickedBtnDll)
	ON_BN_CLICKED(IDC_BTN_REFRESH, &CInjectorDlg::OnBnClickedBtnRefresh)
	ON_BN_CLICKED(IDC_BTN_INJECT, &CInjectorDlg::OnBnClickedBtnInject)
	ON_BN_CLICKED(IDC_BTN_EJECT, &CInjectorDlg::OnBnClickedBtnEject)
	ON_BN_CLICKED(IDC_BTN_GLOBAL, &CInjectorDlg::OnBnClickedBtnCodeInject)
	ON_BN_CLICKED(IDC_BUTTON2, &CInjectorDlg::OnBnClickedButtonCodeEject)
	ON_WM_SYSCOMMAND()
END_MESSAGE_MAP()


// CInjectorDlg message handlers

BOOL CInjectorDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	CMenu *pMenu = GetSystemMenu(FALSE);

	AppendMenu(pMenu->m_hMenu, MF_SEPARATOR, NULL, NULL);
	AppendMenu(pMenu->m_hMenu, MF_STRING, DEF_ID_ABOUT_DLG, "About ...");

	// Process list
	m_listProc.SetExtendedStyle(LVS_EX_FULLROWSELECT);

	m_listProc.InsertColumn(COL_PROCLIST_PID, "PID", LVCFMT_LEFT, 70);
	m_listProc.InsertColumn(COL_PROCLIST_PROCNAME, "Name", LVCFMT_LEFT, 120);

	// Result list
	m_listDllResult.SetExtendedStyle(LVS_EX_FULLROWSELECT);

	m_listDllResult.InsertColumn(COL_RESULTLIST_PID, "PID", LVCFMT_LEFT, 70);
	m_listDllResult.InsertColumn(COL_RESULTLIST_PROCNAME, "Proc", LVCFMT_LEFT, 100);
	m_listDllResult.InsertColumn(COL_RESULTLIST_DLLNAME, "DLL Name", LVCFMT_LEFT, 120);
	m_listDllResult.InsertColumn(COL_RESULTLIST_DLLPATH, "DLL Path", LVCFMT_LEFT, 250);

	m_listCodeResult.SetExtendedStyle(LVS_EX_FULLROWSELECT);

	m_listCodeResult.InsertColumn(COL_RESULTLIST_PID, "PID", LVCFMT_LEFT, 70);
	m_listCodeResult.InsertColumn(COL_RESULTLIST_PROCNAME, "Proc", LVCFMT_LEFT, 100);
	m_listCodeResult.InsertColumn(COL_RESULTLIST_DLLNAME, "DLL Name", LVCFMT_LEFT, 120);
	m_listCodeResult.InsertColumn(COL_RESULTLIST_DLLPATH, "DLL Path", LVCFMT_LEFT, 250);

	RefreshProcList();

	// Log
	m_nLogLevel = 1;
	
	UpdateData(FALSE);

	return TRUE;  // return TRUE  unless you set the focus to a control
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CInjectorDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CInjectorDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CInjectorDlg::OnBnClickedBtnDll()
{
	TCHAR szFilter[] = "Dynamic Link Library (*.dll)|*.dll|";

	CFileDialog dlgFile(TRUE, ".dll", NULL, OFN_EXPLORER | OFN_FILEMUSTEXIST, szFilter);

	if ( dlgFile.DoModal() == IDCANCEL )
		return;

	m_strDllPath = dlgFile.GetPathName();

	UpdateData(FALSE);
}

BOOL CInjectorDlg::RefreshProcList()
{
	PROCESSENTRY32	proc;
	HANDLE			hProcSnapshot	= NULL;
	TCHAR			szPID[13]		= {0, };
	int				nListIndex		= 0;

	HANDLE			hProc			= NULL;
	TCHAR			szPath[1024]	= {0, };
	TCHAR*			pWindowText		= NULL;
	DWORD			dwTextLen		= 0;

	m_listProc.DeleteAllItems();

	proc.dwSize = sizeof(PROCESSENTRY32);
	hProcSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	
	if ( hProcSnapshot == INVALID_HANDLE_VALUE )
		return FALSE;

	Process32First(hProcSnapshot, &proc);

	do
	{
		if ( proc.th32ProcessID == GetCurrentProcessId() ||
			proc.th32ProcessID < 100 )
			continue;

		sprintf(szPID, "0x%08X", proc.th32ProcessID);
		m_listProc.InsertItem(nListIndex, szPID);
		m_listProc.SetItemData(nListIndex, proc.th32ProcessID);

		m_listProc.SetItem(nListIndex, COL_PROCLIST_PROCNAME, LVIF_TEXT, proc.szExeFile, 0, 0, 0, NULL);

		hProc = OpenProcess(MAXIMUM_ALLOWED, FALSE, proc.th32ProcessID);
		if ( hProc == NULL )
			continue;
		
		GetModuleFileNameEx(hProc, 0, szPath, sizeof(szPath)-1);
		m_listProc.SetItem(nListIndex, 2, LVIF_TEXT, szPath, 0, 0, 0, NULL);
	} while ( Process32Next(hProcSnapshot, &proc) );

	return TRUE;
}
void CInjectorDlg::OnBnClickedBtnRefresh()
{
	RefreshProcList();
}

void CInjectorDlg::OnBnClickedBtnInject()
{
	map<DWORD, CString>				mapSelectedPID;
	map<DWORD, CString>::iterator	itSelectedPID;

	int		nSelectedIndex	= 0;
	int		nPosDLLName		= 0;
	DWORD	dwSelectedPID	= 0;
	char	szPID[13]		= {0, };
	CString strDLLName		= "";

	UpdateData();

	m_strDllPath.Trim();

	if ( m_strDllPath.GetLength() == 0 )
	{
		MessageBox("Select a DLL");
		return;
	}

	if ( _access(m_strDllPath, 0) == -1 )
	{
		MessageBox("The DLL file isn\'t exist."); 
		return;
	}

	nPosDLLName = m_strDllPath.ReverseFind('\\');
	if ( nPosDLLName == -1 )
		strDLLName = m_strDllPath;
	else
		strDLLName = m_strDllPath.Mid(nPosDLLName + 1);

	nSelectedIndex = m_listProc.GetNextItem(-1, LVNI_SELECTED);
	while ( nSelectedIndex != -1 )
	{
		dwSelectedPID = m_listProc.GetItemData(nSelectedIndex);
		mapSelectedPID[dwSelectedPID] = m_listProc.GetItemText(nSelectedIndex, COL_PROCLIST_PROCNAME);

		nSelectedIndex = m_listProc.GetNextItem(nSelectedIndex, LVNI_SELECTED);
	}

	if ( mapSelectedPID.size() == 0 )
	{
		MessageBox("Select a process");
		return;
	}

	for ( itSelectedPID = mapSelectedPID.begin(); itSelectedPID != mapSelectedPID.end(); itSelectedPID++ )
	{
		int nListIndex = m_listDllResult.GetItemCount();

		if ( !InjectDll(itSelectedPID->first, m_strDllPath) )
			continue;

		sprintf(szPID, "0x%08X", itSelectedPID->first);
		
		m_listDllResult.InsertItem(nListIndex, szPID);
		m_listDllResult.SetItemData(nListIndex, itSelectedPID->first);
		m_listDllResult.SetItem(nListIndex, COL_RESULTLIST_PROCNAME, LVIF_TEXT, itSelectedPID->second, 0, 0, 0, NULL);	
		m_listDllResult.SetItem(nListIndex, COL_RESULTLIST_DLLNAME, LVIF_TEXT, strDLLName, 0, 0, 0, NULL);	
		m_listDllResult.SetItem(nListIndex, COL_RESULTLIST_DLLPATH, LVIF_TEXT, m_strDllPath, 0, 0, 0, NULL);

		m_mapDllInfo[itSelectedPID->first] = m_strDllPath;
	}
}

void CInjectorDlg::OnBnClickedBtnEject()
{
	map<DWORD, CString>::iterator itInjectedInfo;

	vector<int>				vecSelectedIndex;
	vector<int>::iterator	itSelectedIndex;

	int		nSelectedIndex		= 0;
	int		nPosDLLName			= 0;
	DWORD	dwSelectedPID		= 0;
	char	szPID[13]			= {0, };
	CString strInjectedDllName	= "";
	int		i					= 0;
	
	nSelectedIndex = m_listDllResult.GetNextItem(-1, LVNI_SELECTED);
	while ( nSelectedIndex != -1 )
	{
		vecSelectedIndex.push_back(nSelectedIndex);

		nSelectedIndex = m_listDllResult.GetNextItem(nSelectedIndex, LVNI_SELECTED);
	}

	if ( vecSelectedIndex.size() == 0 )
	{
		MessageBox("Select a Injected Information.");
		return;
	}
	
	itSelectedIndex = vecSelectedIndex.end();

	for ( i = 0; i < vecSelectedIndex.size(); i++)
	{
		itSelectedIndex--;

		dwSelectedPID = m_listDllResult.GetItemData(*itSelectedIndex);

		itInjectedInfo = m_mapDllInfo.find(dwSelectedPID);
		if ( itInjectedInfo == m_mapDllInfo.end() )
			continue;

		if ( !EjectDll(dwSelectedPID, itInjectedInfo->second) )
			continue;

		m_listDllResult.DeleteItem(*itSelectedIndex);
	}
}

void CInjectorDlg::OnBnClickedBtnCodeInject()
{
	map<DWORD, CString>				mapSelectedPID;
	map<DWORD, CString>::iterator	itSelectedPID;

	CInjectionInfo	info;

	DWORD			dwPID				= 0;
	char			szPID[13]			= {0, };
	char			szProcName[_MAX_PATH] = {0, };
	int				nSelectedIndex		= 0;
	int				nResultListIndex	= m_listCodeResult.GetItemCount();
	int				nPosDLLName			= 0;
	CString			strDLLName			= "";
	DWORD			dwSelectedPID		= 0;
	int				nListIndex			= 0;

	UpdateData();

	m_strDllPath.Trim();

	if ( m_strDllPath.GetLength() == 0 )
	{
		MessageBox("Select a DLL");
		return;
	}

	if ( _access(m_strDllPath, 0) == -1 )
	{
		MessageBox("The DLL file isn\'t exist."); 
		return;
	}

	nPosDLLName = m_strDllPath.ReverseFind('\\');
	if ( nPosDLLName == -1 )
		strDLLName = m_strDllPath;
	else
		strDLLName = m_strDllPath.Mid(nPosDLLName + 1);

	nSelectedIndex = m_listProc.GetNextItem(-1, LVNI_SELECTED);
	while ( nSelectedIndex != -1 )
	{
		dwSelectedPID = m_listProc.GetItemData(nSelectedIndex);
		mapSelectedPID[dwSelectedPID] = m_listProc.GetItemText(nSelectedIndex, COL_PROCLIST_PROCNAME);

		nSelectedIndex = m_listProc.GetNextItem(nSelectedIndex, LVNI_SELECTED);
	}

	if ( mapSelectedPID.size() == 0 )
	{
		MessageBox("Select a process");
		return;
	}

	for ( itSelectedPID = mapSelectedPID.begin(); itSelectedPID != mapSelectedPID.end(); itSelectedPID++)
	{
		info.Initialize();
		info.SetDLLPath(m_strDllPath);

		nListIndex = m_listCodeResult.GetItemCount();

		if ( !InjectCode(itSelectedPID->first, m_strDllPath, info) )
			continue;

		sprintf(szPID, "0x%08X", itSelectedPID->first);
		
		m_listCodeResult.InsertItem(nListIndex, szPID);
		m_listCodeResult.SetItemData(nListIndex, itSelectedPID->first);
		m_listCodeResult.SetItem(nListIndex, COL_RESULTLIST_PROCNAME, LVIF_TEXT, itSelectedPID->second, 0, 0, 0, NULL);	
		m_listCodeResult.SetItem(nListIndex, COL_RESULTLIST_DLLNAME, LVIF_TEXT, strDLLName, 0, 0, 0, NULL);	
		m_listCodeResult.SetItem(nListIndex, COL_RESULTLIST_DLLPATH, LVIF_TEXT, m_strDllPath, 0, 0, 0, NULL);

		m_mapCodeInfo[itSelectedPID->first] = info;
	}
}

void CInjectorDlg::OnBnClickedButtonCodeEject()
{
	map<DWORD, CInjectionInfo>::iterator itInjectedInfo;

	vector<int>				vecSelectedIndex;
	vector<int>::iterator	itSelectedIndex;

	int		nSelectedIndex		= 0;
	int		nPosDLLName			= 0;
	DWORD	dwSelectedPID		= 0;
	char	szPID[13]			= {0, };
	CString strInjectedDllName	= "";
	int		i					= 0;

	nSelectedIndex = m_listCodeResult.GetNextItem(-1, LVNI_SELECTED);
	while(nSelectedIndex != -1)
	{
		vecSelectedIndex.push_back(nSelectedIndex);

		nSelectedIndex = m_listCodeResult.GetNextItem(nSelectedIndex, LVNI_SELECTED);
	}

	if ( vecSelectedIndex.size() == 0 )
	{
		MessageBox("Select a Injected Information.");
		return;
	}
	
	itSelectedIndex = vecSelectedIndex.end();

	for ( i = 0; i < vecSelectedIndex.size(); i++)
	{
		itSelectedIndex--;

		dwSelectedPID = m_listCodeResult.GetItemData(*itSelectedIndex);

		itInjectedInfo = m_mapCodeInfo.find(dwSelectedPID);
		if ( itInjectedInfo == m_mapCodeInfo.end() )
			continue;

		if ( !EjectCode(itInjectedInfo->first, itInjectedInfo->second) )
			continue;

		m_listCodeResult.DeleteItem(*itSelectedIndex);
	}
}


void CInjectorDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	switch ( nID )
	{
	case DEF_ID_ABOUT_DLG:
		CAboutDlg dlg;
		dlg.DoModal();
		break;
	}

	CDialog::OnSysCommand(nID, lParam);
}
