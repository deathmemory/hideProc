#pragma once
#include <Tlhelp32.h>

namespace ProcessHelper
{

	static BOOL ScanDllInProcess(CString strProcName, CString strDllName)
	{
		BOOL bRet = FALSE;
		DWORD dwPID = 0;
		HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
		PROCESSENTRY32* processInfo = new PROCESSENTRY32;
		processInfo->dwSize = sizeof(PROCESSENTRY32);
		while(Process32Next(hSnapShot,processInfo)!=FALSE)
		{
			if(strProcName.CompareNoCase(processInfo->szExeFile) == 0)
			{
				dwPID = processInfo->th32ProcessID;
				break;
			}
		}
		CloseHandle(hSnapShot);
		delete processInfo;

		if (dwPID)
		{
			bRet = ScanDllInProcess(dwPID, strDllName);
		}
		return bRet;
	}

	static BOOL ScanDllInProcess(DWORD dwPID, CString strDllName)
	{
		BOOL bRet = FALSE;
		MODULEENTRY32 pe32;
		// ��ʹ������ṹ֮ǰ�����������Ĵ�С
		pe32.dwSize = sizeof(pe32); 
		// ������������ģ����һ������
		//276Ϊĳ���̵�ID
		HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
		if(hProcessSnap == INVALID_HANDLE_VALUE)
		{       
			//��������ʧ��
			return bRet;  
		}

		// �������̿��գ�������ʾÿ�����̵���Ϣ
		BOOL bMore = Module32First(hProcessSnap, &pe32);
		while(bMore)
		{       
			// 			printf("\n[DLL NAME]\t%s\n",pe32.szModule);
			// 			printf("[DLL PATH]\t%s\n",pe32.szExePath);
			if ( strDllName.CompareNoCase(pe32.szModule) == 0)
			{
				bRet = TRUE;
				break;
			}

			bMore = Module32Next(hProcessSnap, &pe32);
		}
		// ��Ҫ���������snapshot����
		CloseHandle(hProcessSnap);

		return bRet;
	}

	static DWORD ScanProcess(CString strProcName)
	{
		HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
		PROCESSENTRY32* processInfo = new PROCESSENTRY32;
		processInfo->dwSize = sizeof(PROCESSENTRY32);
		DWORD dwRet = 0;
		while(Process32Next(hSnapShot,processInfo)!=FALSE)
		{
			if(strProcName.CompareNoCase(processInfo->szExeFile) == 0)
			{
				dwRet = processInfo->th32ProcessID;
				delete processInfo;
				return dwRet;
			}
		}
		CloseHandle(hSnapShot);
		delete processInfo;
		return dwRet;
	}

	static BOOL KillProcByName(CString strProcName)
	{
		HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
		//���ڻ�������н��̵���Ϣ��
		//����hSnapShot�г�ȡ���ݵ�һ��PROCESSENTRY32�ṹ��
		//����ṹ������һ�����̣���ToolHelp32 API��һ���֡�
		//��ȡ���ݿ�Process32First()��Process32Next()������������
		//�������Process32Next()������ԭ���ǣ�
		//BOOL WINAPI Process32Next(HANDLE hSnapshot,LPPROCESSENTRY32 lppe);
		PROCESSENTRY32* processInfo = new PROCESSENTRY32;
		// ��������PROCESSENTRY32��dwSize��Ա��ֵ ;
		processInfo->dwSize = sizeof(PROCESSENTRY32);
		//���ｫ���վ����PROCESSENTRY32�ṹ����Process32Next()��
		//ִ��֮��PROCESSENTRY32 �ṹ����ý��̵���Ϣ��ѭ��������ֱ����������FALSE��
		//printf("****************��ʼ�оٽ���****************\n");
		while(Process32Next(hSnapShot,processInfo)!=FALSE)
		{
			// 		char szBuf[MAX_PATH];
			// 		wcstombs(szBuf, processInfo->szExeFile, MAX_PATH);
			if(strProcName.CompareNoCase(processInfo->szExeFile) == 0)
			{
				int ID = processInfo->th32ProcessID;
				HANDLE hProcess;
				// ���������ú��� TerminateProcess()��ֹ���̣�
				// ����������PROCESS_ALL_ACCESS
				hProcess = OpenProcess(PROCESS_ALL_ACCESS,TRUE,ID);
				if(hProcess == NULL)
				{
					//qDebug("�򿪽���ʧ�� !\n");
					delete processInfo;
					return FALSE;
				}
				TerminateProcess(hProcess,0);
				CloseHandle(hProcess);
			}
		}
		CloseHandle(hSnapShot);
		delete processInfo;
		return TRUE;
	}

	static BOOL SupendProcess(DWORD dwPid, DWORD dwExceptThdId = -1)
	{
		THREADENTRY32 th32;
		th32.dwSize = sizeof(th32);
		BOOL bRet = TRUE;
		if (0 <= dwPid)
			return FALSE;
		HANDLE hThreadSnap=::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
		if( INVALID_HANDLE_VALUE != hThreadSnap )
		{
			if ( Thread32First(hThreadSnap, &th32) )
			{
				do
				{
					if(th32.th32OwnerProcessID == dwPid && th32.th32ThreadID != dwExceptThdId)
					{ 
						HANDLE oth =  OpenThread (THREAD_ALL_ACCESS,FALSE,th32.th32ThreadID);
						if(-1 == (::SuspendThread(oth)))
						{
							bRet = FALSE;
						}
						CloseHandle(oth);
					}
				}while(::Thread32Next(hThreadSnap,&th32));
			}
			else
				bRet = FALSE;
		}
		else
			bRet = FALSE;
		::CloseHandle(hThreadSnap);
		return bRet;
	}

	static BOOL SupendProcess(LPCTSTR lpszProcName, DWORD dwExceptThdId = -1)
	{
		DWORD dwPid = ScanProcess(lpszProcName);
		if (0 == dwPid)
			return FALSE;
		else
			return SupendProcess(dwPid, dwExceptThdId);
	}

	static BOOL ResumeProcess(DWORD dwPid, DWORD dwExceptThdId = -1)
	{
		THREADENTRY32 th32;
		th32.dwSize = sizeof(th32);
		BOOL bRet = TRUE;
		if (0 <= dwPid)
			return FALSE;
		HANDLE hThreadSnap=::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
		if( INVALID_HANDLE_VALUE != hThreadSnap )
		{
			if ( Thread32First(hThreadSnap, &th32) )
			{
				do
				{
					if(th32.th32OwnerProcessID == dwPid && th32.th32ThreadID != dwExceptThdId)
					{ 
						DWORD dwCount = 0;
						HANDLE oth =  OpenThread (THREAD_ALL_ACCESS,FALSE,th32.th32ThreadID);
						while( (dwCount = ::ResumeThread(oth)) > 0);
						
						CloseHandle(oth);
					}
				}while(::Thread32Next(hThreadSnap,&th32));
			}
			else
				bRet = FALSE;
		}
		else
			bRet = FALSE;
		::CloseHandle(hThreadSnap);
		return bRet;
	}

	static BOOL ResumeProcess(LPCTSTR lpszProcName, DWORD dwExceptThdId = -1)
	{
		DWORD dwPid = ScanProcess(lpszProcName);
		if (0 == dwPid)
			return FALSE;
		else
			return ResumeProcess(dwPid, dwExceptThdId);
	}

	static PVOID GetProcAddressEx(HANDLE hProc, HMODULE hModule, LPCSTR lpProcName)
	{
		PVOID pAddress = NULL;
		SIZE_T OptSize;
		IMAGE_DOS_HEADER DosHeader;
		SIZE_T ProcNameLength = lstrlenA(lpProcName) + sizeof(CHAR);//'\0'

		//��DOSͷ
		if (ReadProcessMemory(hProc, hModule, &DosHeader, sizeof(DosHeader), &OptSize))
		{
			IMAGE_NT_HEADERS NtHeader;

			//��NTͷ
			if (ReadProcessMemory(hProc, (PVOID)((SIZE_T)hModule + DosHeader.e_lfanew), &NtHeader, sizeof(NtHeader), &OptSize))
			{
				IMAGE_EXPORT_DIRECTORY ExpDir;
				SIZE_T ExportVirtualAddress = NtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

				//�������
				if (ExportVirtualAddress && ReadProcessMemory(hProc, (PVOID)((SIZE_T)hModule + ExportVirtualAddress), &ExpDir, sizeof(ExpDir), &OptSize))
				{
					if (ExpDir.NumberOfFunctions)
					{
						//x64����:��ַ������RVA������������4�ֽڻ���8�ֽ�???
						SIZE_T *pProcAddressTable = (SIZE_T *)GlobalAlloc(GPTR, ExpDir.NumberOfFunctions * sizeof(SIZE_T));

						//��������ַ��
						if (ReadProcessMemory(hProc, (PVOID)((SIZE_T)hModule + ExpDir.AddressOfFunctions), pProcAddressTable, ExpDir.NumberOfFunctions * sizeof(PVOID), &OptSize))
						{
							//x64����:����������RVA������������4�ֽڻ���8�ֽ�???
							SIZE_T *pProcNamesTable = (SIZE_T *)GlobalAlloc(GPTR, ExpDir.NumberOfNames * sizeof(SIZE_T));

							//���������Ʊ�
							if (ReadProcessMemory(hProc, (PVOID)((SIZE_T)hModule + ExpDir.AddressOfNames), pProcNamesTable, ExpDir.NumberOfNames * sizeof(PVOID), &OptSize))
							{
								CHAR *pProcName = (CHAR *)GlobalAlloc(GPTR, ProcNameLength);

								//������������
								for (DWORD i = 0; i < ExpDir.NumberOfNames; i++)
								{
									if (ReadProcessMemory(hProc, (PVOID)((SIZE_T)hModule + pProcNamesTable[i]), pProcName, ProcNameLength, &OptSize))
									{
										if (RtlEqualMemory(lpProcName, pProcName, ProcNameLength))
										{
											//x64����:�����ڵ�ַ��������������������2�ֽڻ���???
											WORD NameOrdinal;

											//��ȡ�����ڵ�ַ�������
											if (ReadProcessMemory(hProc, (PVOID)((SIZE_T)hModule + ExpDir.AddressOfNameOrdinals + sizeof(NameOrdinal) * i), &NameOrdinal, sizeof(NameOrdinal), &OptSize))
											{
												pAddress = (PVOID)((SIZE_T)hModule + pProcAddressTable[NameOrdinal]);
											}
											break;//for
										}
									}
								}
								GlobalFree(pProcName);
							}
							GlobalFree(pProcNamesTable);
						}
						GlobalFree(pProcAddressTable);
					}
				}
			}
		}
		return pAddress;
	}

};