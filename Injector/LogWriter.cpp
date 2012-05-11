/************************************************************************
    This file is part of BM Injector.

	FILE : LogWriter.cpp
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
#include "LogWriter.h"

CListBox* CLogWriter::m_pListLog = NULL;
int CLogWriter::m_nLogLevel = 2;

CLogWriter::CLogWriter()
{
}

CLogWriter::~CLogWriter()
{
}

BOOL CLogWriter::Initialize(CListBox *pListLog)
{
	m_pListLog = pListLog;

	return TRUE;
}

BOOL CLogWriter::SetLogLevel(int nLogLevel)
{
	m_nLogLevel = nLogLevel;

	return TRUE;
}

BOOL CLogWriter::WriteLog(int nLogLevel, LPCSTR lpFormat, ...)
{
	CString strMsg = "";
	CString strLog = "";
	va_list pArg;

	if ( nLogLevel > m_nLogLevel )
		return TRUE;

	if ( m_pListLog == NULL )
		return FALSE;

	switch (nLogLevel)
	{
	case 1:	strLog = "[ERROR] ";	break;
	case 2: strLog = "[WARN]  ";	break;
	case 3: strLog = "[INFO]  ";	break;
	case 4: strLog = "[DEBUG] ";	break;
	}

	va_start(pArg, lpFormat);

	strMsg.Format(lpFormat, pArg);

	va_end(pArg);

	strLog += strMsg;

	m_pListLog->SetCurSel(m_pListLog->AddString(strLog));

	return TRUE;
}