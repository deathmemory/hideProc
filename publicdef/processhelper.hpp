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
		// 在使用这个结构之前，先设置它的大小
		pe32.dwSize = sizeof(pe32); 
		// 给进程内所有模块拍一个快照
		//276为某进程的ID
		HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
		if(hProcessSnap == INVALID_HANDLE_VALUE)
		{       
			//建立快照失败
			return bRet;  
		}

		// 遍历进程快照，轮流显示每个进程的信息
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
		// 不要忘记清除掉snapshot对象
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
		//现在获得了所有进程的信息。
		//将从hSnapShot中抽取数据到一个PROCESSENTRY32结构中
		//这个结构代表了一个进程，是ToolHelp32 API的一部分。
		//抽取数据靠Process32First()和Process32Next()这两个函数。
		//这里仅用Process32Next()，他的原形是：
		//BOOL WINAPI Process32Next(HANDLE hSnapshot,LPPROCESSENTRY32 lppe);
		PROCESSENTRY32* processInfo = new PROCESSENTRY32;
		// 必须设置PROCESSENTRY32的dwSize成员的值 ;
		processInfo->dwSize = sizeof(PROCESSENTRY32);
		//这里将快照句柄和PROCESSENTRY32结构传给Process32Next()。
		//执行之后，PROCESSENTRY32 结构将获得进程的信息。循环遍历，直到函数返回FALSE。
		//printf("****************开始列举进程****************\n");
		while(Process32Next(hSnapShot,processInfo)!=FALSE)
		{
			// 		char szBuf[MAX_PATH];
			// 		wcstombs(szBuf, processInfo->szExeFile, MAX_PATH);
			if(strProcName.CompareNoCase(processInfo->szExeFile) == 0)
			{
				int ID = processInfo->th32ProcessID;
				HANDLE hProcess;
				// 现在我们用函数 TerminateProcess()终止进程：
				// 这里我们用PROCESS_ALL_ACCESS
				hProcess = OpenProcess(PROCESS_ALL_ACCESS,TRUE,ID);
				if(hProcess == NULL)
				{
					//qDebug("打开进程失败 !\n");
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

		//读DOS头
		if (ReadProcessMemory(hProc, hModule, &DosHeader, sizeof(DosHeader), &OptSize))
		{
			IMAGE_NT_HEADERS NtHeader;

			//读NT头
			if (ReadProcessMemory(hProc, (PVOID)((SIZE_T)hModule + DosHeader.e_lfanew), &NtHeader, sizeof(NtHeader), &OptSize))
			{
				IMAGE_EXPORT_DIRECTORY ExpDir;
				SIZE_T ExportVirtualAddress = NtHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

				//读输出表
				if (ExportVirtualAddress && ReadProcessMemory(hProc, (PVOID)((SIZE_T)hModule + ExportVirtualAddress), &ExpDir, sizeof(ExpDir), &OptSize))
				{
					if (ExpDir.NumberOfFunctions)
					{
						//x64待定:地址数组存放RVA的数据类型是4字节还是8字节???
						SIZE_T *pProcAddressTable = (SIZE_T *)GlobalAlloc(GPTR, ExpDir.NumberOfFunctions * sizeof(SIZE_T));

						//读函数地址表
						if (ReadProcessMemory(hProc, (PVOID)((SIZE_T)hModule + ExpDir.AddressOfFunctions), pProcAddressTable, ExpDir.NumberOfFunctions * sizeof(PVOID), &OptSize))
						{
							//x64待定:名称数组存放RVA的数据类型是4字节还是8字节???
							SIZE_T *pProcNamesTable = (SIZE_T *)GlobalAlloc(GPTR, ExpDir.NumberOfNames * sizeof(SIZE_T));

							//读函数名称表
							if (ReadProcessMemory(hProc, (PVOID)((SIZE_T)hModule + ExpDir.AddressOfNames), pProcNamesTable, ExpDir.NumberOfNames * sizeof(PVOID), &OptSize))
							{
								CHAR *pProcName = (CHAR *)GlobalAlloc(GPTR, ProcNameLength);

								//遍历函数名称
								for (DWORD i = 0; i < ExpDir.NumberOfNames; i++)
								{
									if (ReadProcessMemory(hProc, (PVOID)((SIZE_T)hModule + pProcNamesTable[i]), pProcName, ProcNameLength, &OptSize))
									{
										if (RtlEqualMemory(lpProcName, pProcName, ProcNameLength))
										{
											//x64待定:函数在地址数组索引的数据类型是2字节还是???
											WORD NameOrdinal;

											//获取函数在地址表的索引
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