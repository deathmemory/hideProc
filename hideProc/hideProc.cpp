// hideProc.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "ProcessWatchThread.h"

#define INJECTPROCNAME				_T("GarenaMessenger.exe")

CProcessWatchThread g_thread;
CProcessWatchThread g_Rundll32thread;
int _tmain(int argc, _TCHAR* argv[])
{
	SYSTEMTIME st;
	TCHAR tstrCurrentDir[MAX_PATH] = {0};
	int nPathLen = 0;
	GetModuleFileName(NULL, tstrCurrentDir, MAX_PATH);
	TCHAR* lptstrDirRoot = _tcsrchr(tstrCurrentDir, _T('\\'));
	if (lptstrDirRoot)
	{
		nPathLen = lptstrDirRoot-tstrCurrentDir;
		tstrCurrentDir[nPathLen+1] = 0x00;
	}
	CString path = tstrCurrentDir + CString(_T("injector.dll"));
 	//g_thread.SetConfig(path, _T("GarenaMessenger.exe"));
	g_thread.SetConfig(path, INJECTPROCNAME);
 	g_thread.StartWatch();
	//g_Rundll32thread.SetConfig(path, _T("rundll32.exe"));
	//g_Rundll32thread.StartWatch();
	printf("keep this proccess running...123 !\r\n");
	system("pause");
	system("taskkill /f /im rundll32.exe /t");
	return 0;
}

