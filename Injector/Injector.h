/************************************************************************
    This file is part of BM Injector.

	FILE : Injector.h
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

#ifndef __AFXWIN_H__
	#error "include 'stdafx.h' before including this file for PCH"
#endif

#include "resource.h"		// main symbols


// CInjectorApp:
// See Injector.cpp for the implementation of this class
//

class CInjectorApp : public CWinApp
{
public:
	CInjectorApp();

	virtual BOOL InitInstance();

	DECLARE_MESSAGE_MAP()
};

extern CInjectorApp theApp;