/************************************************************************
    This file is part of BM Injector.

	FILE : InjectorDlg.h
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

// InjectorDlg.h : header file
//

#pragma once
#include "afxwin.h"
#include "afxcmn.h"
#include <map>
#include "InjectionInfo.h"

using namespace std;

#define DEF_ID_ABOUT_DLG	6003

typedef enum
{
	COL_PROCLIST_PID = 0,
	COL_PROCLIST_PROCNAME,
} ENUM_COL_PROCLIST;

typedef enum
{
	COL_RESULTLIST_PID = 0,
	COL_RESULTLIST_PROCNAME,
	COL_RESULTLIST_DLLNAME,
	COL_RESULTLIST_DLLPATH,
} ENUM_COL_RESULTLIST;

typedef enum
{
	LIST_PROCESS = 0,
	LIST_INJECTED_PROCESS,
	LIST_STARTED_PROCESS,
} ENUM_LIST_TYPE;

// CInjectorDlg dialog
class CInjectorDlg : public CDialog
{
// Construction
public:
	CInjectorDlg(CWnd* pParent = NULL);	// standard constructor

	BOOL RefreshProcList();
// Dialog Data
	enum { IDD = IDD_Injector_DIALOG };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support

	afx_msg void OnBnClickedBtnDll();
	afx_msg void OnBnClickedBtnRefresh();
	afx_msg void OnBnClickedBtnInject();
	afx_msg void OnBnClickedBtnEject();
	afx_msg void OnBnClickedBtnCodeInject();
	afx_msg void OnBnClickedButtonCodeEject();
// Implementation
protected:
	HICON m_hIcon;
	CListBox m_listLog;

	map<DWORD, CInjectionInfo> m_mapCodeInfo;
	map<DWORD, CString> m_mapDllInfo;

	CListCtrl m_listDllResult;
	CListCtrl m_listCodeResult;

	BOOL DeleteResultItem(DWORD dwPID);
	BOOL GetSelectedProcesses(int nListType, map<DWORD, CString> &mapSelectedProcess);

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
private:
	CString m_strDllPath;
	CButton m_btnGlobal;
	CListCtrl m_listProc;
	CComboBox m_cboLogLevel;
	int m_nLogLevel;
public:
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnCbnSelchangeComboLoglevel();
};
