#include "pch.h"

extern wchar_t VirusTotalApiKey[128];

// Get information from the server
// Returns a char * buffer that is allocated in this function; caller's obligation to free the buffer
char* VT_GetFileReport(const wchar_t* URI) {

	// The buffer to hold the response
	char* ResponseBuffer = NULL;

	// Array of accept types
	PCWSTR AcceptTypes[] = { L"application/json", NULL };

	// Return Error Code
	DWORD dwErrorCode = ERROR_SUCCESS;

	// Internet handles
	HINTERNET hInternet, hConnect, hRequest;

	// Authorization Header
	wchar_t* AuthHeader = NULL;

	// Check to make sure that we have a valid API key, server address, and server port
	// and build the Authorization Header
	if (wcslen(VirusTotalApiKey) > 0) {
		AuthHeader = (wchar_t*)malloc(128 * sizeof(wchar_t));
		ZeroMemory(AuthHeader, 128 * sizeof(wchar_t));
		StringCchPrintf(AuthHeader, 128, L"x-apikey: %s", VirusTotalApiKey);
	}
	// Check to make sure we are connected to the Internet...
	DWORD dwInternetConnectionFlags = 0;
	if (!InternetGetConnectedState(&dwInternetConnectionFlags, 0)) {
		dwErrorCode = VT_ERROR_NO_INTERNET;
		SetLastError(dwErrorCode);
		return NULL;
	}

	// Open the connection
	hInternet = InternetOpen(L"VirusTotal X-Ways Forensics Plugin",
		INTERNET_OPEN_TYPE_PRECONFIG,
		NULL,
		NULL,
		0);

	if (hInternet) {
		// Connect
		hConnect = InternetConnect(hInternet,
			L"www.virustotal.com",
			INTERNET_DEFAULT_HTTPS_PORT,
			NULL,
			NULL,
			INTERNET_SERVICE_HTTP,
			0,
			0);

		if (hConnect) {
			// Make the HTTP SSL connection
			hRequest = HttpOpenRequestW(hConnect,
				L"GET",
				URI,
				NULL,
				NULL,
				AcceptTypes,
				INTERNET_FLAG_SECURE | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID,
				0);

			if (hRequest) {
				// Send the HTTP request
				if (HttpSendRequestW(hRequest, AuthHeader, (DWORD)wcslen(AuthHeader), NULL, 0)) {
					DWORD dwContentLength = 0;
					DWORD length = sizeof(DWORD);

					// Get the content length and make sure our buffer is big enough to handle it
					HttpQueryInfo(hRequest,
						HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER,
						&dwContentLength,
						&length,
						NULL);

					// Get the status code
					DWORD dwStatusCode = 0;
					length = sizeof(DWORD);

					HttpQueryInfo(hRequest,
						HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
						&dwStatusCode,
						&length, NULL);


					if (dwStatusCode == 200) {
						ResponseBuffer = (char*)malloc(dwContentLength + 1);
						ZeroMemory(ResponseBuffer, dwContentLength + 1);

						DWORD dwBytesRead = 0;
						DWORD offset = 0;

						// Read the response
						DWORD dwBufRemaining = dwContentLength;

						while (dwBufRemaining > 0) {
							if (dwBufRemaining > 1024)
								InternetReadFile(hRequest, ResponseBuffer + offset, 1024, &dwBytesRead);
							else
								InternetReadFile(hRequest, ResponseBuffer + offset, dwBufRemaining, &dwBytesRead);

							if (dwBytesRead == 0) {
								break;
							}
							else {
								if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
									dwErrorCode = VT_ERROR_BUFFER_OVERRUN;
								}
								offset += dwBytesRead;
								dwBufRemaining -= dwBytesRead;
							}
						}
					}
					else if (dwStatusCode == 404) {
						dwErrorCode = ERROR_FILE_NOT_FOUND;
					}
					else if (dwStatusCode == 403) {
						dwErrorCode = VT_ERROR_AUTHORIZATION;
					}
				}
				else {
					DWORD dwError = GetLastError();
					int foo = 0;
				}
				InternetCloseHandle(hRequest);
			}
			else {
				DWORD dwError = GetLastError();
				dwErrorCode = VT_ERROR_HTTP;
			}
			InternetCloseHandle(hConnect);
		}
		else {
			dwErrorCode = VT_ERROR_CONNECTING;
		}
		InternetCloseHandle(hInternet);
	}
	else {
		dwErrorCode = VT_ERROR_CONNECTING;
	}

	// Free the Auth Header
	if (AuthHeader != NULL) {
		free(AuthHeader);
		AuthHeader = NULL;
	}

	// Set the error code
	SetLastError(dwErrorCode);

	// Return success
	return ResponseBuffer;
}