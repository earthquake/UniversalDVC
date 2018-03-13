/*
* MIT License
*
* Copyright(c) 2018 Balazs Bucsay
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files(the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions :
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/

#include "stdafx.h"
#include "resource.h"
#include "UDVC-Plugin.h"

#pragma comment(lib, "Ws2_32.lib")

#define UDVC_CHANNEL_NAME "UniversalDVC"

struct arguments {
	DWORD enabled;
	DWORD mode; // 0 sock listen(); 1 sock connect(); 2 namedpipe
	WCHAR *namedpipename;
	WCHAR *ip;
	WCHAR *port;
};

struct threadhandles {
	SOCKET sock = NULL;
	HANDLE pipe = NULL;
};

struct threadargs {
	struct arguments *running_args;
	struct threadhandles *threadhandle;
	IWTSVirtualChannel *m_ptrChannel = NULL;
};

using namespace ATL;

#define CHECK_QUIT_HR( _x_ )    if(FAILED(hr)) { return hr; }

class ATL_NO_VTABLE UDVCPlugin :
	public CComObjectRootEx<CComMultiThreadModel>,
	public CComCoClass<UDVCPlugin, &CLSID_CompReg>,
	public IWTSPlugin,
	public IWTSVirtualChannelCallback,
	public IWTSListenerCallback
{
public:
	CComPtr<IWTSVirtualChannel> m_ptrChannel;

	DECLARE_REGISTRY_RESOURCEID(IDR_UDVCPLUGIN)

	BEGIN_COM_MAP(UDVCPlugin)
		COM_INTERFACE_ENTRY(IWTSPlugin)
		COM_INTERFACE_ENTRY(IWTSVirtualChannelCallback)
		COM_INTERFACE_ENTRY(IWTSListenerCallback)
	END_COM_MAP()

	DECLARE_PROTECT_FINAL_CONSTRUCT()


	HRESULT FinalConstruct()
	{
		return S_OK;
	}

	void FinalRelease()
	{
	}

	// IWTSPlugin.
	//
	HRESULT STDMETHODCALLTYPE
		Initialize(IWTSVirtualChannelManager *pChannelMgr);

	HRESULT STDMETHODCALLTYPE Connected();

	HRESULT STDMETHODCALLTYPE Disconnected(DWORD dwDisconnectCode)
	{
		// Prevent C4100 "unreferenced parameter" warnings.
		dwDisconnectCode;
		return S_OK;
	}

	HRESULT STDMETHODCALLTYPE Terminated()
	{
		return S_OK;
	}

	VOID SetChannel(IWTSVirtualChannel *pChannel, struct threadargs *pTa);

	// IWTSVirtualChannelCallback
	//
	HRESULT STDMETHODCALLTYPE OnDataReceived(ULONG cbSize, __in_bcount(cbSize) BYTE *pBuffer);
	
	HRESULT STDMETHODCALLTYPE OnClose()
	{
		return m_ptrChannel->Close();
	}

	HRESULT STDMETHODCALLTYPE
		OnNewChannelConnection(
			__in IWTSVirtualChannel *pChannel,
			__in_opt BSTR data,
			__out BOOL *pbAccept,
			__out IWTSVirtualChannelCallback **ppCallback);

	// non-inherited ones

	struct threadargs ta, *pta;
	struct arguments running_args;
	struct threadhandles threadhandle;

	static VOID UDVCPlugin::DebugPrint(HRESULT hrDbg, __in_z LPWSTR fmt, ...);
	LONG UDVCPlugin::GetDWORDRegKey(HKEY hKey, WCHAR *strValueName, DWORD *nValue);
	LONG UDVCPlugin::GetStringRegKey(HKEY hKey, WCHAR *strValueName, WCHAR **strValue);
	BOOL UDVCPlugin::GetRegistrySettings();
	static DWORD WINAPI UDVCPlugin::ListenerThread(PVOID param);
	static DWORD WINAPI UDVCPlugin::RsWcThread(PVOID param);

};

OBJECT_ENTRY_AUTO(__uuidof(CompReg), UDVCPlugin)


VOID UDVCPlugin::DebugPrint(HRESULT hrDbg, __in_z LPWSTR fmt, ...)
{
	HRESULT	hr;
	TCHAR	Buffer[DEBUG_PRINT_BUFFER_SIZE];
	size_t	Len;

	hr = StringCchPrintf(Buffer, DEBUG_PRINT_BUFFER_SIZE, TEXT("[hr=0x%8x]"), hrDbg);
	assert(SUCCEEDED(hr)); // buffer is sure to be big enough

	hr = StringCchLength(Buffer, DEBUG_PRINT_BUFFER_SIZE, &Len);
	assert(SUCCEEDED(hr)); // StringCchPrintf is supposed to always NULL term

	va_list argptr;
	va_start(argptr, fmt);

	hr = StringCchVPrintf(Buffer + Len, DEBUG_PRINT_BUFFER_SIZE - Len,
		fmt, argptr);

	// the above could fail but we don't care since we
	// should get a NULL terminated partial string

	// insert terminating eol (despite failure)
	hr = StringCchLength(Buffer, DEBUG_PRINT_BUFFER_SIZE, &Len);
	assert(SUCCEEDED(hr)); // again there should be a NULL term

	if (Len < DEBUG_PRINT_BUFFER_SIZE - 1)
	{
		Len++;
		Buffer[Len] = TEXT('\0');
	}

	Buffer[Len - 1] = TEXT('\n');
	OutputDebugString(Buffer);
}

LONG UDVCPlugin::GetDWORDRegKey(HKEY hKey, WCHAR *strValueName, DWORD *nValue)
{
	DWORD dwBufferSize(sizeof(DWORD));
	DWORD nResult;
	LONG nError;

	if ((nError = RegQueryValueEx(hKey, strValueName, 0, NULL, (LPBYTE)&nResult, &dwBufferSize)) == ERROR_SUCCESS)
	{
		*nValue = nResult;
	}
	return nError;
}

LONG UDVCPlugin::GetStringRegKey(HKEY hKey, WCHAR *strValueName, WCHAR **strValue)
{
	LPVOID szTemp = NULL;
	DWORD buflen = 255;
	LONG nError;

	if ((szTemp = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (size_t)buflen)) == NULL)
	{
		DebugPrint(GetLastError(), L"[-] Error allocating heap for read buffer %ld", GetLastError());
		return -1;
	}

	if ((nError = RegQueryValueExW(hKey, strValueName, 0, NULL, (LPBYTE)szTemp, &buflen)) != ERROR_SUCCESS)
	{
		HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, szTemp);
		szTemp = NULL;
	}
	*strValue = (WCHAR *)szTemp;

	return nError;
}

BOOL UDVCPlugin::GetRegistrySettings()
{
	HKEY hKey;
	LONG lRes;
	WCHAR *szTemp;

	if ((lRes = RegOpenKeyEx(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Terminal Server Client\\Default\\AddIns\\UDVC-Plugin\\", 0, KEY_READ, &hKey)) != ERROR_SUCCESS)
	{
		DebugPrint(lRes, L"[-] Error opening registry hive/key");
		return FALSE;
	}

	GetDWORDRegKey(hKey, L"enabled", &running_args.enabled);
	GetDWORDRegKey(hKey, L"mode", &(running_args.mode));
	if ((running_args.mode == 0) || (running_args.mode == 1))
	{
		GetStringRegKey(hKey, L"ip", &szTemp);
		if (szTemp != NULL)
		{
			if (wcslen(szTemp) < 16)
			{
				running_args.ip = szTemp;
			}
			else
			{
				MessageBox(NULL, L"IP too long. Please fix it under the following key:\r\nHKCU\\SOFTWARE\\Microsoft\\Terminal Server Client\\Default\\AddIns\\UDVC-Plugin\\", L"Registry value error", MB_OK);
			}
		}
		GetStringRegKey(hKey, L"port", &szTemp);
		if (szTemp != NULL)
		{
			if (wcslen(szTemp) < 6)
			{
				running_args.port = szTemp;
			}
			else
			{
				MessageBox(NULL, L"Port too long. Please fix it under the following key:\r\nHKCU\\SOFTWARE\\Microsoft\\Terminal Server Client\\Default\\AddIns\\UDVC-Plugin\\", L"Registry value error", MB_OK);
			}
		}
	}
	if (running_args.mode == 2)
	{
		GetStringRegKey(hKey, L"namedpipename", &szTemp);
		if (szTemp != NULL)
		{
			if (wcsncmp(szTemp, L"\\\\.\\pipe\\", 9))
			{
				MessageBox(NULL, L"Named pipe name has to start with: \\\\.\\pipe\\\r\nPlease fix it under the following key:\r\nHKCU\\SOFTWARE\\Microsoft\\Terminal Server Client\\Default\\AddIns\\UDVC-Plugin\\", L"Registry value error", MB_OK);
			}
			else
			{
				running_args.namedpipename = szTemp;
			}
		}
	}
	
	return TRUE;
}


// IWTSPlugin::Initialize implementation.
HRESULT UDVCPlugin::Initialize(__in IWTSVirtualChannelManager *pChannelMgr)
{
	HRESULT	hr;
	CComObject<UDVCPlugin> *pListenerCallback;
	CComPtr<UDVCPlugin> ptrListenerCallback;
	CComPtr<IWTSListener> ptrListener;
	WCHAR	enabledmsg[256];

	running_args.enabled = 0;
	running_args.mode = 0;
	running_args.port = L"31337";
	running_args.namedpipename = L"\\\\.\\pipe\\UDVC_default";
	running_args.ip = L"127.0.0.1";

	if (!GetRegistrySettings())
	{
		DebugPrint(-1, L"[-] Could not access the registry settings");
	}

	if (!running_args.enabled)
	{
		DebugPrint(0, L"[*] Plugin disabled");
		return -1;
	}

	if (running_args.mode == 0)
		wnsprintf(enabledmsg, 255, L"The UDVC plugin is enabled. When the server binary gets executed, it will listen on: %s:%s", running_args.ip, running_args.port);
	if (running_args.mode == 1)
		wnsprintf(enabledmsg, 255, L"The UDVC plugin is enabled. When the server binary gets executed, it will connect to: %s:%s", running_args.ip, running_args.port);
	if (running_args.mode == 2)
		wnsprintf(enabledmsg, 255, L"The UDVC plugin is enabled. When the server binary gets executed, it will listen on: %s", running_args.namedpipename);

	MessageBox(NULL, enabledmsg, L"UDVC plugin is enabled", MB_OK | MB_ICONWARNING);


	// Create an instance of the CSampleListenerCallback object.
	hr = CComObject<UDVCPlugin>::CreateInstance(&pListenerCallback);
	CHECK_QUIT_HR("CSampleListenerCallback::CreateInstance");
	ptrListenerCallback = pListenerCallback;

	// Attach the callback to the endpoint.
	hr = pChannelMgr->CreateListener(
		UDVC_CHANNEL_NAME,
		0,
		(UDVCPlugin*)ptrListenerCallback,
		&ptrListener);
	CHECK_QUIT_HR("CreateListener");

	return hr;
}

HRESULT STDMETHODCALLTYPE UDVCPlugin::Connected()
{
	return S_OK;
}

DWORD UDVCPlugin::ListenerThread(PVOID param)
{
	struct threadargs *threadarg = (struct threadargs *)param;
	WSADATA		wsaData;
	ADDRINFOW	*result = NULL;
	ADDRINFOW	hints;
	SOCKET		s, c;
	HANDLE		hNamedPipe = NULL;
	int			ret;
	u_long		blocking = 0;

	if (threadarg->running_args->mode == 0)
	{
		DebugPrint(0, L"[*] Setting up server socket");
		if ((ret = WSAStartup(MAKEWORD(2, 2), &wsaData)) != 0)
		{
			DebugPrint(ret, L"WSAStartup() failed with error: %ld", ret);
			return -1;
		}

		ZeroMemory(&hints, sizeof(hints));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
		hints.ai_flags = AI_PASSIVE;

		if ((ret = GetAddrInfoW(threadarg->running_args->ip, threadarg->running_args->port, &hints, &result)) != 0) {
			DebugPrint(ret, L"[-] GetAddrInfoW() failed with error: %ld", ret);
			WSACleanup();
			return -1;
		}

		if ((s = socket(result->ai_family, result->ai_socktype, result->ai_protocol)) == INVALID_SOCKET) {
			DebugPrint(WSAGetLastError(), L"[-] socket() failed with error: %ld", WSAGetLastError());
			FreeAddrInfoW(result);
			WSACleanup();
			return -1;
		}

		if ((ret = bind(s, result->ai_addr, (int)result->ai_addrlen)) == SOCKET_ERROR) {
			DebugPrint(WSAGetLastError(), L"[-] bind() failed with error: %ld", WSAGetLastError());
			FreeAddrInfoW(result);
			closesocket(s);
			WSACleanup();
			return -1;
		}

		FreeAddrInfoW(result);
		DebugPrint(0, L"[*] Listening on: %s:%s", threadarg->running_args->ip, threadarg->running_args->port);

		if ((ret = listen(s, SOMAXCONN)) == SOCKET_ERROR) {
			DebugPrint(WSAGetLastError(), L"[-] listen() failed with error: %ld", WSAGetLastError());
			closesocket(s);
			WSACleanup();
			return -1;
		}

		if ((c = accept(s, NULL, NULL)) == INVALID_SOCKET) {
			DebugPrint(WSAGetLastError(), L"[-] accept() failed with error: %ld", WSAGetLastError());
			closesocket(s);
			WSACleanup();
			return -1;
		}
		DebugPrint(0, L"[+] Client connected");

		closesocket(s);

		ret = ioctlsocket(c, FIONBIO, &blocking);
		if (ret != NO_ERROR)
		{
			DebugPrint(ret, L"[-] ioctlsocket() failed with error: %ld", ret);
			closesocket(c);
			WSACleanup();
			return -1;
		}
		threadarg->threadhandle->sock = c;
	}
	if (threadarg->running_args->mode == 1)
	{
		DebugPrint(0, L"[*] Setting up client socket");
		if ((ret = WSAStartup(MAKEWORD(2, 2), &wsaData)) != 0)
		{
			DebugPrint(ret, L"[-] WSAStartup() failed with error: %ld", ret);
			return -1;
		}

		ZeroMemory(&hints, sizeof(hints));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
		hints.ai_flags = AI_PASSIVE;

		if ((ret = GetAddrInfoW(threadarg->running_args->ip, threadarg->running_args->port, &hints, &result)) != 0) {
			DebugPrint(ret, L"[-] GetAddrInfoW() failed with error: %ld", ret);
			WSACleanup();
			return -1;
		}

		if ((c = socket(result->ai_family, result->ai_socktype, result->ai_protocol)) == INVALID_SOCKET) {
			DebugPrint(WSAGetLastError(), L"[-] socket() failed with error: %ld", WSAGetLastError());
			FreeAddrInfoW(result);
			WSACleanup();
			return -1;
		}

		if ((ret = connect(c, result->ai_addr, (int)result->ai_addrlen)) == SOCKET_ERROR) {
			DebugPrint(WSAGetLastError(), L"[-] connect() failed with error: %ld", WSAGetLastError());
			FreeAddrInfoW(result);
			closesocket(c);
			WSACleanup();
			return -1;
		}
		FreeAddrInfoW(result);
		DebugPrint(0, L"[*] Connected to: %s:%s", threadarg->running_args->ip, threadarg->running_args->port);

		ret = ioctlsocket(c, FIONBIO, &blocking);
		if (ret != NO_ERROR)
		{
			DebugPrint(ret, L"[-] ioctlsocket() failed with error: %ld", ret);
			closesocket(c);
			WSACleanup();
			return -1;
		}
		threadarg->threadhandle->sock = c;
	}
	if (threadarg->running_args->mode == 2)
	{
		DebugPrint(0, L"[*] Setting up named pipe");

		if ((hNamedPipe = CreateNamedPipe(threadarg->running_args->namedpipename,
			PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
			PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 4096, 4096,
			NMPWAIT_USE_DEFAULT_WAIT, NULL)) == INVALID_HANDLE_VALUE)
		{
			DebugPrint(GetLastError(), L"[-] CreateNamedPipe() failed with: %ld", GetLastError());
			return -1;
		}

		DebugPrint(0, L"[*] Listening on pipe: %s\n", threadarg->running_args->namedpipename);
		if (!ConnectNamedPipe(hNamedPipe, NULL))
		{
			DebugPrint(GetLastError(), L"[-] ConnectNamedPipe() failed with: %ld", GetLastError());
			return -1;
		}

		threadarg->threadhandle->pipe = hNamedPipe;
		DebugPrint(0, L"[+] Client connected to the pipe.");
	}

	return RsWcThread(param);
}

DWORD WINAPI UDVCPlugin::RsWcThread(PVOID param)
{
	struct threadargs *threadarg = (struct threadargs *)param;
	DWORD	dw;
	BOOL    bSucc;
	HANDLE  hEvent_pipe;
	BYTE	*readBuf;
	DWORD	heapsize = 4096;

	if ((readBuf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, heapsize)) == NULL)
	{
		DebugPrint(GetLastError(), L"[-] Error allocating heap for read buffer %ld", GetLastError());
		return -1;
	}

	hEvent_pipe = CreateEvent(NULL, FALSE, FALSE, NULL);
	OVERLAPPED Overlapped_pipe = { 0 };
	Overlapped_pipe.hEvent = hEvent_pipe;

	while (TRUE)
	{
		if (threadarg->threadhandle->sock)
		{
			if ((dw = recv(threadarg->threadhandle->sock, (char *)readBuf, heapsize, 0)) == 0)
			{
				DebugPrint(WSAGetLastError(), L"[-] [RsWc] recv() failed with error %d, exiting thread...\n", WSAGetLastError());
				return -1;
			}
		}
		if (threadarg->threadhandle->pipe)
		{
			bSucc = ReadFile(threadarg->threadhandle->pipe, readBuf, heapsize, &dw, &Overlapped_pipe);
			if (!bSucc)
			{
				if (GetLastError() == ERROR_IO_PENDING)
				{
					dw = WaitForSingleObject(Overlapped_pipe.hEvent, INFINITE);
					bSucc = GetOverlappedResult(threadarg->threadhandle->pipe, &Overlapped_pipe, &dw, FALSE);
				}
			}
			if (!bSucc)
			{
				DebugPrint(GetLastError(), L"[-] [RsWc] ReadFile()/WaitForSingleObject() error: %ld\n", GetLastError());
				return -1;
			}

			if (ResetEvent(Overlapped_pipe.hEvent) == FALSE)
			{
				DebugPrint(GetLastError(), L"[-] [RsWc] ResetEvent() failed with error = %d\n", GetLastError());
				return -1;
			}
		}

		if (threadarg->m_ptrChannel != NULL)
			threadarg->m_ptrChannel->Write(dw, readBuf, NULL);
	}

	return 0;
}

// IWTSListenerCallback::OnNewChannelConnection implementation.
HRESULT UDVCPlugin::OnNewChannelConnection(__in IWTSVirtualChannel *pChannel,
	__in_opt BSTR data, __out BOOL *pbAccept, __out IWTSVirtualChannelCallback **ppCallback)
{
	HRESULT		hr;
	DWORD		dwThreadId;
	CComObject<UDVCPlugin> *pCallback;
	CComPtr<UDVCPlugin> ptrCallback;

	// Prevent C4100 "unreferenced parameter" warnings.
	data;

	*pbAccept = FALSE;

	hr = CComObject<UDVCPlugin>::CreateInstance(&pCallback);
	CHECK_QUIT_HR("UDVCPlugin::CreateInstance");
	ptrCallback = pCallback;

	ptrCallback->SetChannel(pChannel, &ta);

	ta.running_args = &running_args;
	ta.threadhandle = &threadhandle;
	ta.m_ptrChannel = pChannel;

	running_args.enabled = 0;
	running_args.mode = 0;
	running_args.port = L"31337";
	running_args.namedpipename = L"\\\\.\\pipe\\UDVC_default";
	running_args.ip = L"127.0.0.1";

	if (!GetRegistrySettings())
	{
		DebugPrint(-1, L"[-] Could not access the registry settings");
	}

	HANDLE hListenerThread = CreateThread(
		NULL,
		0,
		&UDVCPlugin::ListenerThread,
		&ta,
		0,
		&dwThreadId);

	*ppCallback = ptrCallback;
	(*ppCallback)->AddRef();

	*pbAccept = TRUE;

	return hr;
}

VOID UDVCPlugin::SetChannel(IWTSVirtualChannel *pChannel, struct threadargs *pTa)
{
	m_ptrChannel = pChannel;
	pta	= pTa;
}

HRESULT STDMETHODCALLTYPE UDVCPlugin::OnDataReceived(ULONG cbSize, __in_bcount(cbSize) BYTE *pBuffer)
{
	DWORD       ret, dw;
	HANDLE      hEvent;
	BOOL        bSucc;

	hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	OVERLAPPED  Overlapped = { 0 };
	Overlapped.hEvent = hEvent;

	if (pta->threadhandle->sock)
	{
		if ((ret = send(pta->threadhandle->sock, (char *)pBuffer, cbSize, 0)) == SOCKET_ERROR)
		{
			DebugPrint(WSAGetLastError(), L"[-] [RsWc] send() failed with error %ld", WSAGetLastError());
			return -1;
		}
	}
	if (pta->threadhandle->pipe)
	{
		bSucc = WriteFile(pta->threadhandle->pipe, pBuffer, cbSize, &ret, &Overlapped);
		if (!bSucc)
		{
			if (GetLastError() == ERROR_IO_PENDING)
			{
				dw = WaitForSingleObject(Overlapped.hEvent, INFINITE);
				bSucc = GetOverlappedResult(pta->threadhandle->pipe, &Overlapped, &ret, FALSE);
			}
		}
		if (!bSucc)
		{
			DebugPrint(GetLastError(), L"[-] [RsWc] WriteFile()/WaitForSingleObject() error: %ld", GetLastError());
			return -1;
		}
	}

	return ret;
}