#pragma once

#include "Thread.h"

// CProcessWatchThread 
#define  WM_AIR_EXIT WM_USER+5000
class CProcessWatchThread :  public CThreadImpl<CProcessWatchThread>
{
public:
	CProcessWatchThread():CThreadImpl<CProcessWatchThread>(CREATE_SUSPENDED)
	{
		m_hNotifyWindow = NULL;
		m_bCancel = false;
	};
           // protected constructor used by dynamic creation
	virtual ~CProcessWatchThread();

public:
	
	static CProcessWatchThread * NewInstance();
	BOOL InitInstance();
	int ExitInstance();
	void StartWatch();
	void CancelWatch();
	void SetNotifyWindow(HWND hWnd);
	void UnLoadLibrary();
	BOOL GetExeFileName(HANDLE hProcess,TCHAR *exePath,DWORD exePathSize);
	DWORD Run()
	{
		if ( !InitInstance())
			return 1;
		// Do something useful...
		return 0;
	}
	void SetConfig(CString path, LPCTSTR lpszDll);
	CString strEXE;
	CString strDLL;
	CString m_strPath;
protected:
	HWND m_hNotifyWindow;
	bool m_bCancel;
};


