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

#include <winsock2.h>
#include <Ws2tcpip.h>
#include <windows.h>
#include <wtsapi32.h>
#include <pchannel.h>
#include <crtdbg.h>
#include <stdio.h>


#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "Ws2_32.lib")

#define UDVC_CHANNEL_NAME "UniversalDVC"

DWORD OpenDynamicChannel(LPCSTR szChannelName, HANDLE *phFile);
DWORD WINAPI RcWsThread(PVOID param);
DWORD WINAPI RsWcThread(PVOID param);

struct arguments {
	BOOL mode; // 0 namedpipe; 1 socket
	WCHAR *namedpipename;
	WCHAR *ip;
	WCHAR *port;
	BYTE priority;
} running_args;

struct threadhandles {
	HANDLE hRDP = NULL;
	SOCKET sock = NULL;
	HANDLE pipe = NULL;
};

VOID usage(WCHAR *cmdname)
{
	wprintf(L"Usage: %s [-s [-p port [-h ip]] | -m [-n name]] [-0 | -1 | -2 | -3]\n"
		"Socket mode -s (default):\n"
		"\t-p port\t  port to bind the listener\n"
		"\t-i ip\t  ip to bind the listener (default: 127.0.0.1)\n\n"
		"Named pipe mode -m:\n"
		"\t-n name\t  name of the named pipe (by default: \"\\\\.\\pipe\\UDVC_{RDP SESSION NUMBER}\")\n\n"
		"Data transfer priority parameters:\n"
		"\t-0\t  real time\t\t(WTS_CHANNEL_OPTION_DYNAMIC_PRI_REAL)\n"
		"\t-1\t  high priority\t\t(WTS_CHANNEL_OPTION_DYNAMIC_PRI_HIGH) - default\n"
		"\t-2\t  medium priority\t(WTS_CHANNEL_OPTION_DYNAMIC_PRI_MED)\n"
		"\t-3\t  low priority\t\t(WTS_CHANNEL_OPTION_DYNAMIC_PRI_LOW)\n", cmdname);

	return;
}

BOOL parse_argv(INT argc, __in_ecount(argc) WCHAR **argv)
{
	int num = 0;

	while (num < argc - 1)
	{
		num++;

		if (wcsncmp(argv[num], L"-", 1))
		{
			wprintf(L"[-] Invalid argument: %s\n", argv[num]);
			usage(argv[0]);
			return FALSE;
		}

		switch (argv[num][1])
		{
			case 'h':
				usage(argv[0]);
				return FALSE;
			case 'm':
				running_args.mode = TRUE;
				break;
			case 'n':
				num++;

				if (wcsncmp(argv[num], L"\\\\.\\pipe\\", 9))
				{
					wprintf(L"[-] Named pipe name has to start with: \\\\.\\pipe\\\n");
					usage(argv[0]);
					return FALSE;
				}
				running_args.namedpipename = argv[num];
				break;

			case 's':
				running_args.mode = FALSE;
				break;
			case 'p':
				num++;

				running_args.port = argv[num];
				break;
			case 'i':
				num++;

				running_args.ip = argv[num];
				break;

			case '0':
				running_args.priority = WTS_CHANNEL_OPTION_DYNAMIC_PRI_REAL;
				break;
			case '1':
				running_args.priority = WTS_CHANNEL_OPTION_DYNAMIC_PRI_HIGH;
				break;
			case '2':
				running_args.priority = WTS_CHANNEL_OPTION_DYNAMIC_PRI_MED;
				break;
			case '3':
				running_args.priority = WTS_CHANNEL_OPTION_DYNAMIC_PRI_LOW;
				break;

			default:
				wprintf(L"[-] Invalid argument: %s\n", argv[num]);
				usage(argv[0]);
				return FALSE;
		}
	}
	return TRUE;
}

ULONG GetCurrentSessionId(void) {
	LPTSTR pBuf;
	DWORD len;
	ULONG ret;

	if (!WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTSSessionId, &pBuf, &len))
	{
		return -1;
	}

	ret = (ULONG)*pBuf;
	WTSFreeMemory(pBuf);
	
	return ret;
}

INT _cdecl wmain(INT argc, __in_ecount(argc) WCHAR **argv)
{
	DWORD rc;
	HANDLE hFile;
	WSADATA wsaData;
	ADDRINFOW *result = NULL;
	ADDRINFOW hints;
	SOCKET s, c;
	WCHAR tempnamepipename[24];
	HANDLE hNamedPipe = NULL;
	int ret;
	ULONG sessionId;

	struct threadhandles threadhandle;

	sessionId = GetCurrentSessionId();
	wsprintf(tempnamepipename, L"\\\\.\\pipe\\UDVC_%08X", sessionId);

	running_args.mode = FALSE;
	running_args.port = L"31337";
	running_args.priority = 4;
	running_args.namedpipename = tempnamepipename;
	running_args.ip = L"127.0.0.1";

	wprintf(L"Universal Dynamic Virtual Channel server application\n\n");

	if (argc > 1)
		if (!parse_argv(argc, argv))
			return -1;

	rc = OpenDynamicChannel(UDVC_CHANNEL_NAME, &hFile);
	if (ERROR_SUCCESS != rc)
	{
		return -1;
	}

	if (!running_args.mode)
	{
		wprintf(L"[*] Setting up socket\n");
		if ((ret = WSAStartup(MAKEWORD(2, 2), &wsaData)) != 0)
		{ 
			wprintf(L"[-] WSAStartup() failed with error: %d\n", ret);
			return -1;
		}

		ZeroMemory(&hints, sizeof(hints));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
		hints.ai_flags = AI_PASSIVE;

		if ((ret = GetAddrInfoW(running_args.ip, running_args.port, &hints, &result)) != 0) {
			wprintf(L"[-] GetAddrInfoW() failed with error: %ld\n", ret);
			WSACleanup();
			return -1;
		}

		if ((s = socket(result->ai_family, result->ai_socktype, result->ai_protocol)) == INVALID_SOCKET) {
			wprintf(L"[-] socket() failed with error: %ld\n", WSAGetLastError());
			FreeAddrInfoW(result);
			WSACleanup();
			return -1;
		}

		if ((ret = bind(s, result->ai_addr, (int)result->ai_addrlen)) == SOCKET_ERROR) {
			wprintf(L"[-] bind() failed with error: %ld\n", WSAGetLastError());
			FreeAddrInfoW(result);
			closesocket(s);
			WSACleanup();
			return -1;
		}
		FreeAddrInfoW(result);
		wprintf(L"[*] Listening on: %s:%s\n", running_args.ip, running_args.port);

		if ((ret = listen(s, SOMAXCONN)) == SOCKET_ERROR) {
			wprintf(L"[-] listen() failed with error: %ld\n", WSAGetLastError());
			closesocket(s);
			WSACleanup();
			return -1;
		}

		if ((c = accept(s, NULL, NULL)) == INVALID_SOCKET) {
			wprintf(L"[-] accept() failed with error: %ld\n", WSAGetLastError());
			closesocket(s);
			WSACleanup();
			return -1;
		}
		wprintf(L"[+] Client connected\n");

		closesocket(s);

		u_long blocking = 0;
		ret = ioctlsocket(c, FIONBIO, &blocking);
		if (ret != NO_ERROR)
		{
			wprintf(L"[-] ioctlsocket() failed with error: %ld\n", ret);
			closesocket(c);
			WSACleanup();
			return -1;
		}
		threadhandle.sock = c;
	}
	else
	{
		wprintf(L"[*] Setting up named pipe\n");

		if ((hNamedPipe = CreateNamedPipe(running_args.namedpipename, 
			PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
			PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 4096, 4096, 
			NMPWAIT_USE_DEFAULT_WAIT, NULL)) == INVALID_HANDLE_VALUE)
		{
			wprintf(L"[-] CreateNamedPipe() failed with: %ld", GetLastError());
			return -1;
		}

		wprintf(L"[*] Listening on pipe: %s\n", running_args.namedpipename);
		if (!ConnectNamedPipe(hNamedPipe, NULL))
		{
			wprintf(L"[-] ConnectNamedPipe() failed with: %ld", GetLastError());
			return -1;
		}

		threadhandle.pipe = hNamedPipe;
		wprintf(L"[+] Client connected to the pipe.\n");
	}

	threadhandle.hRDP = hFile;

	wprintf(L"[*] Starting thread RsWc\n");
	DWORD dwThreadId;
	HANDLE hReadThread = CreateThread(
		NULL,
		0,
		RsWcThread,
		&threadhandle,
		0,
		&dwThreadId);

	wprintf(L"[*] Starting thread RcWs\n");
	HANDLE hWriteThread = CreateThread(
		NULL,
		0,
		RcWsThread,
		&threadhandle,
		0,
		&dwThreadId);

	HANDLE ah[] = { hReadThread, hWriteThread };
	printf("[*] Waiting for threads to exit...\n");
	WaitForMultipleObjects(2, ah, TRUE, INFINITE);

	if (running_args.mode)
	{
		if ((ret = shutdown(c, SD_BOTH)) == SOCKET_ERROR) {
			wprintf(L"[-] shutdown() failed with error: %d\n", WSAGetLastError());
			closesocket(c);
			WSACleanup();
			return -1;
		}
		closesocket(c);
		WSACleanup();
	}
	else
	{
		CloseHandle(hNamedPipe);
	}

	CloseHandle(hReadThread);
	CloseHandle(hWriteThread);
	CloseHandle(hFile);

	return 0;
}

/*
*  Open a dynamic channel with the name given in szChannelName.
*  The output file handle can be used in ReadFile/WriteFile calls.
*/
DWORD OpenDynamicChannel(
	LPCSTR szChannelName,
	HANDLE *phFile)
{
	HANDLE hWTSHandle = NULL;
	HANDLE hWTSFileHandle;
	PVOID vcFileHandlePtr = NULL;
	DWORD len;
	DWORD rc = ERROR_SUCCESS;
	BOOL fSucc;

	hWTSHandle = WTSVirtualChannelOpenEx(WTS_CURRENT_SESSION, (LPSTR)szChannelName,
		WTS_CHANNEL_OPTION_DYNAMIC);
	if (NULL == hWTSHandle)
	{
		rc = GetLastError();
		goto exitpt;
	}

	fSucc = WTSVirtualChannelQuery(hWTSHandle, WTSVirtualFileHandle,
		&vcFileHandlePtr, &len);
	if (!fSucc)
	{
		rc = GetLastError();
		goto exitpt;
	}
	if (len != sizeof(HANDLE))
	{
		rc = ERROR_INVALID_PARAMETER;
		goto exitpt;
	}

	hWTSFileHandle = *(HANDLE *)vcFileHandlePtr;

	fSucc = DuplicateHandle(GetCurrentProcess(), hWTSFileHandle, 
		GetCurrentProcess(), phFile, 0, FALSE, DUPLICATE_SAME_ACCESS);

	if (!fSucc)
	{
		rc = GetLastError();
		goto exitpt;
	}

	rc = ERROR_SUCCESS;

exitpt:
	if (vcFileHandlePtr)
	{
		WTSFreeMemory(vcFileHandlePtr);
	}
	if (hWTSHandle)
	{
		WTSVirtualChannelClose(hWTSHandle);
	}

	return rc;
}

/* 
 * Thread that reads the socket or named pipe and writes the stream to the 
 * RDP virtual channel. 
 */
DWORD WINAPI RsWcThread(PVOID param)
{
	threadhandles *handles = (threadhandles *)param;
	DWORD   dwWritten;
	DWORD	dw;
	BOOL    bSucc;
	HANDLE  hEvent_rdp, hEvent_pipe;
	char *readBuf;
	DWORD heapsize = 4096;

	if ((readBuf = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, heapsize)) == NULL)
	{
		wprintf(L"[-] Error allocating heap for read buffer %ld", GetLastError());
		return -1;
	}

	hEvent_rdp = CreateEvent(NULL, FALSE, FALSE, NULL);
	OVERLAPPED Overlapped = { 0 };
	Overlapped.hEvent = hEvent_rdp;

	hEvent_pipe = CreateEvent(NULL, FALSE, FALSE, NULL);
	OVERLAPPED Overlapped_pipe = { 0 };
	Overlapped_pipe.hEvent = hEvent_pipe;

	while (TRUE)
	{	
		if (handles->sock)
		{
			if ((dw = recv(handles->sock, readBuf, heapsize, 0)) == 0)
			{
				wprintf(L"[-] [RsWc] recv() failed with error %d, exiting thread...\n", WSAGetLastError());
				return -1;
			}
		}
		if (handles->pipe)
		{
			bSucc = ReadFile(handles->pipe, readBuf, heapsize, &dw, &Overlapped_pipe);
			if (!bSucc)
			{
				if (GetLastError() == ERROR_IO_PENDING)
				{
					dw = WaitForSingleObject(Overlapped_pipe.hEvent, INFINITE);
					bSucc = GetOverlappedResult(handles->pipe, &Overlapped_pipe, &dw, FALSE);
				}
			}
			if (!bSucc)
			{
				wprintf(L"[-] [RsWc] ReadFile()/WaitForSingleObject() error: %ld\n", GetLastError());
				return -1;
			}

			if (ResetEvent(Overlapped_pipe.hEvent) == FALSE)
			{
				wprintf(L"[-] [RsWc] ResetEvent() failed with error = %d\n", GetLastError());
				return -1;
			}
		}

		bSucc = WriteFile(handles->hRDP, readBuf, dw, &dwWritten, &Overlapped);
		if (!bSucc)
		{
			if (GetLastError() == ERROR_IO_PENDING)
			{
				dw = WaitForSingleObject(Overlapped.hEvent, INFINITE);
				bSucc = GetOverlappedResult(handles->hRDP, &Overlapped, &dwWritten, FALSE);
			}
		}
		if (!bSucc)
		{
			wprintf(L"[-] [RsWc] WriteFile()/WaitForSingleObject() error: %ld\n", GetLastError());
			return -1;
		}
	}
	return 0;
}

/* 
 * Thread that reads the RDP virtual channel and writes the stream to the 
 * socket or named pipe. 
 */
DWORD WINAPI RcWsThread(PVOID param)
{
	threadhandles *handles = (threadhandles *)param;
	BYTE        ReadBuffer[CHANNEL_PDU_LENGTH];
	CHANNEL_PDU_HEADER *pHdr = (CHANNEL_PDU_HEADER *)ReadBuffer;
	PBYTE		pData;
	DWORD       dwRead, ret, Flags, dw;
	BOOL        bSucc;
	HANDLE      hEvent;
	char		*bufWrite;
	DWORD		bufWritelen;

	hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	OVERLAPPED  Overlapped = { 0 };
	DWORD TotalRead = 0;

	Overlapped.hEvent = hEvent;
	while (TRUE)
	{
		bSucc = ReadFile(handles->hRDP, ReadBuffer, sizeof(ReadBuffer), &dwRead, &Overlapped);
		if (!bSucc)
		{
			if (GetLastError() == ERROR_IO_PENDING)
			{
				dw = WaitForSingleObject(Overlapped.hEvent, INFINITE);
				bSucc = GetOverlappedResult(handles->hRDP, &Overlapped, &dwRead, FALSE);
			}
		}
		pData = (PBYTE)(pHdr + 1);

		if (!bSucc)
		{
			wprintf(L"[-] [RcWs] ReadFile()/WaitForSingleObject() error: %ld\n", GetLastError());
			return -1;
		}

		if ((ret = ResetEvent(Overlapped.hEvent)) == FALSE)
		{
			wprintf(L"[-] [RcWs] ResetEvent() failed with error = %d\n", GetLastError());
			return -1;
		}

		// no need to pass the header.
		bufWrite = (char *)(pHdr + 1);
		/*
		WSAdata.len = pHdr->length;
		pHdr->length stores the full length of the packet, we only need that 
		was received. Ignoring the header flags as well, we just proxy the 
		bytes. This is not that nice though.
		*/
		bufWritelen = dwRead - sizeof(CHANNEL_PDU_HEADER);
		Flags = 0;

		if (handles->sock)
		{
			if ((ret = send(handles->sock, bufWrite, bufWritelen, 0)) == SOCKET_ERROR)
			{
				wprintf(L"[-] [RsWc] send() failed with error %ld\n", WSAGetLastError());
				return -1;
			}
		}
		if (handles->pipe)
		{
			bSucc = WriteFile(handles->pipe, bufWrite, bufWritelen, &ret, &Overlapped);
			if (!bSucc)
			{
				if (GetLastError() == ERROR_IO_PENDING)
				{
					dw = WaitForSingleObject(Overlapped.hEvent, INFINITE);
					bSucc = GetOverlappedResult(handles->pipe, &Overlapped, &ret, FALSE);
				}
			}
			if (!bSucc)
			{
				wprintf(L"[-] [RsWc] WriteFile()/WaitForSingleObject() error: %ld\n", GetLastError());
				return -1;
			}
		}
	}
	return 0;
}
