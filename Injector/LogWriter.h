/************************************************************************
    This file is part of BM Injector.

	FILE : LogWriter.h
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

#define WRITE_LOG CLogWriter::WriteLog

class CLogWriter
{
public:
	CLogWriter();
	virtual ~CLogWriter();

	static BOOL Initialize(CListBox *pListLog);
	static BOOL SetLogLevel(int nLogLevel);
	static BOOL WriteLog(int nLogLevel, LPCSTR lpFormat, ...);

protected:
	static CListBox *m_pListLog;
	static int m_nLogLevel;
};