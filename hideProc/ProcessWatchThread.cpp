// ProcessWatchThread.cpp : implementation file
//

#include "stdafx.h"
#include <windows.h>
#include "ProcessWatchThread.h"
#include <Psapi.h>
#pragma comment(lib, "Psapi.lib")
#include "../publicdef/publicdef.h"
#include "../publicdef/processhelper.hpp"

CProcessWatchThread::~CProcessWatchThread()
{
}

BOOL CProcessWatchThread::InitInstance()
{
	while (!m_bCancel)
	{
		DWORD dwPid = ProcessHelper::ScanProcess(strEXE);
		if (dwPid)
		{
			HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
			if (hProcess)
			{
				if ( ! ProcessHelper::ScanDllInProcess(dwPid, strDLL) )	// 如果没有此DLL才注入
				{
					LPVOID lpBuffer = VirtualAllocEx(hProcess, NULL, (m_strPath.GetLength() + 1) * sizeof(TCHAR), MEM_COMMIT, PAGE_READWRITE);
					if (lpBuffer)
					{
						DWORD dwWritten;
						WriteProcessMemory(hProcess, lpBuffer, m_strPath, (m_strPath.GetLength() + 1) * sizeof(TCHAR), &dwWritten);
						DWORD dwThreadId;
						HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibrary, lpBuffer, 0, &dwThreadId);
						DWORD dwExit = -1;
						if (hThread)
						{
							WaitForSingleObject(hThread, INFINITE);
							GetExitCodeThread(hThread, &dwExit); 
							CloseHandle(hThread);
						}
						VirtualFreeEx(hProcess, lpBuffer, 0, MEM_DECOMMIT);
						CString str;
						str.Format(_T("DLL: %s, exit:%d"), strDLL, dwExit);
						RECORD_STATIC_INFO(str, CConfig::GetLocalDir());
					}
				}
				else
				{
					TCHAR *ptsz = _T("The dll have injected ...");
					RECORD_STATIC_WARN(ptsz, CConfig::GetLocalDir());
					OutputDebugString(ptsz);
					OutputDebugString(_T("\r\n"));
					while (WaitForSingleObject(hProcess, 0) == WAIT_TIMEOUT && !m_bCancel)
						Sleep(1000);
				}

				CloseHandle(hProcess);
			}
			else
			{
				DWORD dwErr = 0;
				dwErr = GetLastError();
				TCHAR tszMsg[MAX_PATH*2] = {0};
				FormatMessage(
					FORMAT_MESSAGE_FROM_SYSTEM, 
					NULL,
					dwErr,
					0,
					tszMsg,
					MAX_PATH*2,
					NULL
					);
				CString str;
				str.Format(_T("info: %s, pid: %d"), tszMsg, dwPid);
				RECORD_STATIC_ERR(str, CConfig::GetLocalDir());
			}
		}
		Sleep(1000);
	}
	//delete this;
	return FALSE;
}

void CProcessWatchThread::UnLoadLibrary()
{
	DWORD aProcessIds[2048] = {0};
	DWORD dwProcessCount = 0;
	DWORD hDll = 0, dwWritten = 0;
	LPVOID lpFun = NULL;
	LPVOID lpBuf = NULL; 
	HANDLE tThread = NULL; 
	DWORD dwSize = lstrlen(strDLL) * sizeof(TCHAR) + sizeof(TCHAR); 
	if (EnumProcesses(aProcessIds, 2048, &dwProcessCount))
	{
		for (DWORD i = 0; i < dwProcessCount; ++i)
		{
			HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | SYNCHRONIZE, FALSE, aProcessIds[i]);
			if (hProcess)
			{
				TCHAR cExeName[MAX_PATH] = {0};
				if (GetModuleBaseName(hProcess, NULL, cExeName, MAX_PATH))
					if (_tcsicmp(cExeName, strEXE) == 0)
					{
						do 
						{
							lpBuf = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE); 
							WriteProcessMemory(hProcess, lpBuf, (LPVOID)strDLL.GetBuffer(strDLL.GetLength()), dwSize, &dwWritten);
							if( sizeof(TCHAR) == 2 )
								lpFun = GetProcAddress( GetModuleHandle(_T("kernel32.dll")), "GetModuleHandleW" );
							else
								lpFun = GetProcAddress( GetModuleHandle(_T("kernel32.dll")), "GetModuleHandleA" );

							tThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpFun, lpBuf, 0, 0); 
							if (tThread)
							{
								WaitForSingleObject(tThread, INFINITE); 
								GetExitCodeThread(tThread, &hDll); 

								VirtualFreeEx(hProcess, lpBuf, dwSize, MEM_DECOMMIT); 
								CloseHandle(tThread); 
								if( ! hDll ) { CloseHandle(hProcess); return; }
								lpFun = GetProcAddress( GetModuleHandle(_T("kernel32.dll")), "FreeLibraryAndExitThread" ); 
								if (lpFun)
								{
									tThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpFun, (LPVOID)hDll, 0, NULL); 
									if (tThread)
									{
										WaitForSingleObject(tThread, INFINITE); 
										CloseHandle(tThread); 
									}
								}
							}
							
						} while(hDll);
					}
				
				CloseHandle(hProcess);
			}
		}
	}
}

int CProcessWatchThread::ExitInstance()
{
	// TODO:  perform any per-thread cleanup here
	
	return 0;
}


CProcessWatchThread * CProcessWatchThread::NewInstance()
{
	return new CProcessWatchThread;//(CProcessWatchThread *)AfxBeginThread(RUNTIME_CLASS(CProcessWatchThread), 0, 0, CREATE_SUSPENDED, NULL);
}

void CProcessWatchThread::StartWatch()
{
	Resume();
}

void CProcessWatchThread::CancelWatch()
{
	m_bCancel = true;
}

void CProcessWatchThread::SetNotifyWindow( HWND hWnd )
{
	m_hNotifyWindow = hWnd;
}
// CProcessWatchThread message handlers

void CProcessWatchThread::SetConfig(CString path, LPCTSTR lpszEXE)
{
	strEXE = lpszEXE;
	m_strPath = path;
	int idx = path.ReverseFind(_T('\\'));
	strDLL = path.Right(path.GetLength() - idx - 1);
}