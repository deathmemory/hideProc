// stdafx.h : ��׼ϵͳ�����ļ��İ����ļ���
// ���Ǿ���ʹ�õ��������ĵ�
// �ض�����Ŀ�İ����ļ�
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

// TODO: �ڴ˴����ó�����Ҫ������ͷ�ļ�
