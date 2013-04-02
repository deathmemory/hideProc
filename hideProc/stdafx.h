// stdafx.h : 标准系统包含文件的包含文件，
// 或是经常使用但不常更改的
// 特定于项目的包含文件
//

#pragma once

#include "targetver.h"

#include <stdio.h>
#include <tchar.h>
#include <Windows.h>
#include <atlbase.h>
#include <atlapp.h>
#include <atlmisc.h>
class CConfig
{
public:
	static LPCTSTR GetLocalDir()
	{
		return NULL;
	}
};

#define RECORD_STATIC_WARN
#define RECORD_STATIC_INFO
#define RECORD_STATIC_ERR

// TODO: 在此处引用程序需要的其他头文件
