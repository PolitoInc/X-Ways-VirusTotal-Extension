#include "pch.h"

//// Global Variables

// API key to be used for the querying
wchar_t VirusTotalApiKey[128];	

// Number of queries to perform per minute (for rate limiting / free API versions)
// 0 means go as fast as possible
unsigned int QueryRate = 0;	

// The base URL for VirusTotal API lookups
std::wstring VirusTotalAPIEndpoint = std::wstring(L"/api/v3/files/");

// The std::list that is to be used as a queue for lookups
std::list<XWFITEMHASH*> HashLookupQueue;

// CRITICAL_SECTION object for syncrhonization on operations on the HashLookupQueue
CRITICAL_SECTION HashLookupQueueCriticalSection;

// HANDLE for the QueueProcessingThread; intially NULL; thread gets created once the first XWFITEMHASH is inserted
HANDLE hQueueProcessingThread = NULL;

// Exported function called by X-Ways to initialize us
LONG __stdcall XT_Init(DWORD nVersion, DWORD nFlags, HANDLE hMainWnd, struct LicenseInfo* pLicInfo) {
	if (XT_RetrieveFunctionPointers() > 0) {
		// Check that the function pointers we need are available else return -1
		return -1;
	}

	// Check version. We need 17.4 or later.
	if (nVersion < 1740) {
		XWF_OutputMessage(L"Error: This XTension requires X-Ways Forensics version 17.4 or later.", 0);
		return -1;
	}

	// Initialize the CRITICAL_SECTION object for syncrhonization of operations on the queue
	InitializeCriticalSection(&HashLookupQueueCriticalSection);

	std::wstringstream ss;
	ss << L"Processing hashes through VirusTotal, " << QueryRate << L" hashes per minute. Please wait...";
	XWF_OutputMessage(ss.str().c_str(), 0);

	return 1;
}

// Exported function called by X-Ways when the user selects the "About" button
LONG __stdcall XT_About(HANDLE hParentWnd, void* lpReserved) {
	MessageBox((HWND)hParentWnd, L"Polito, Inc.\nCopyright 2022\nVirusTotal Lookup X-Tension", L"VirusTotal Lookup", MB_OK);
	return 0;
}

// Exported function called by X-Ways when preparing for operations and to determine how we are to be called going forward
LONG __stdcall XT_Prepare(HANDLE hVolume, HANDLE hEvidence, DWORD nOpType, void* lpReserved) {
	

	// Only run when refining the volume snapshot or when invoked via the directory browser context menu
	if (nOpType == XT_ACTION_RUN || nOpType == XT_ACTION_RVS || nOpType == XT_ACTION_DBC) {
		return XT_PREPARE_CALLPI;
	}

	return 0;
}

// Exported function called on each item to be processed
LONG __stdcall XT_ProcessItem(LONG nItemID, void* lpReserved) {
	// Ask X-Ways to give us the value of the hash that was computed for this particular item
	BOOL bSuccess = FALSE;
	// Pointer to our hash string buffer
	std::wstring szItemHash;

	// Get the information about the current item
	INT64 nResult = XWF_GetItemInformation(nItemID, XWF_ITEM_INFO_FLAGS, &bSuccess);

	// Check if the hash has already been computed
	if (nResult & XT_HASH1ALREADYCOMPUTED) {
		// retrieve the hash type
		INT64 hashType = XWF_GetVSProp(XWF_VSPROP_HASHTYPE1, NULL);

		// Get the hash in string format
		if (GetHashString(nItemID, hashType, &szItemHash)) {
			// Create a XWFITEMHASH object and add it to the queue
			XWFITEMHASH *itemHash = new XWFITEMHASH();
			itemHash->nItemID = nItemID;
			itemHash->szHash = szItemHash;

			EnterCriticalSection(&HashLookupQueueCriticalSection);
			HashLookupQueue.push_back(itemHash);
			LeaveCriticalSection(&HashLookupQueueCriticalSection);

			if (hQueueProcessingThread == NULL) {
				hQueueProcessingThread = CreateThread(NULL, 0, QueueProcessingFunc, NULL, 0, NULL);
			}
		}
		else {
			XWF_OutputMessage(L"Error converting binary hash to string.", 0);
			return 0;
		}
	}
	else {
		MessageBox(NULL, L"Hash has not been computed", L"Alert", MB_OK);
		// Stop the current operation
		return -1;
	}

	return 0;
}

// Exported function called when we are finishing up our work
LONG __stdcall XT_Done(PVOID lpReserved) {
	// Wait until the thread processing the queue is done
	if (hQueueProcessingThread != NULL) {
		WaitForSingleObject(hQueueProcessingThread, INFINITE);
	}

	XWF_OutputMessage(L"VirusTotal processing complete!", 0);

	return 0;
}


DWORD WINAPI QueueProcessingFunc(LPVOID lpParam) {
	// The buffer to hold the response from VirusTotal
	char* szVTReport = NULL;

	while (HashLookupQueue.size() > 0) {
		// Get the element at the front of the queue
		XWFITEMHASH* itemHash = HashLookupQueue.front();

		// Append the hash to the end of the URL string
		std::wstring URI = VirusTotalAPIEndpoint + itemHash->szHash;

		// Query VirusTotal
		szVTReport = VT_GetFileReport(URI.c_str());

		if (szVTReport != NULL) {
			// Parse the report
			if (!ParseFileReport(szVTReport, itemHash->nItemID)) {
				// Print an error message
				XWF_OutputMessage(L"Unknown error parsing the VirusTotal response.", 0);
			}
		}

		free(szVTReport);

		// Remove the XWFITEMHASH we just processed
		EnterCriticalSection(&HashLookupQueueCriticalSection);
		HashLookupQueue.pop_front();
		LeaveCriticalSection(&HashLookupQueueCriticalSection);

		// Sleep for the appropriate amount of time to prevent rate limiting by VT
		if (QueryRate != 0) {
			Sleep((60 / QueryRate) * 1000);
		}
	}

	return 0;
}

// Read the configuration file;
// This is called when the DLL is first loaded. It loads the API key and query rate values
// into a global variable for later use.
// The configuration file format is expected to be as follows:
// <Virustotal API key>:<Number of queries per minute>
BOOL ReadAPIConfigFile(HMODULE hModule) {
	// Return value
	BOOL bSuccess = FALSE;

	// Zero out the string variables
	ZeroMemory(VirusTotalApiKey, 128 * sizeof(wchar_t));

	// Get the Module Path
	wchar_t FilePath[MAX_PATH];
	GetModuleFileName(hModule, FilePath, MAX_PATH);

	// Zero out the module filename and append the config file name
	wchar_t* substr = wcsrchr(FilePath, '\\');
	if (substr == NULL) {
		return FALSE;
	}

	// Get the index of the last backslash character in the file path
	// FilePath = pointer to beginning of the string; substr = pointer to last backslash
	size_t index = (size_t)(substr - FilePath);

	// Zero out the filename portion of the file path
	ZeroMemory(FilePath + index, (size_t)((MAX_PATH - index) * sizeof(wchar_t)));

	// Append the (expected) name of the config file to the path string
	StringCchCopy(substr, (size_t)(MAX_PATH - index), L"\\vtconfig.txt");

	// Open the file
	HANDLE hFile = CreateFile(FilePath,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hFile != INVALID_HANDLE_VALUE) {
		// Get the file size
		DWORD dwFileSize = GetFileSize(hFile, NULL);

		if (dwFileSize != INVALID_FILE_SIZE) {
			// Read the file contents into a buffer
			char* ConfigFileContents = (char*)malloc(dwFileSize);
			
			if (ConfigFileContents == NULL) {
				return FALSE;
			}

			// Keep track of the number of bytes we read in
			DWORD dwNumberOfBytesRead = 0;

			if (ReadFile(hFile, ConfigFileContents, dwFileSize, &dwNumberOfBytesRead, NULL)) {
				// File should contain single line of the format <API key>:<# queries per minute>
				
				// Convert the file from multibyte to wide character
				int cchConfigFileString = MultiByteToWideChar(CP_UTF8,
					MB_PRECOMPOSED,
					ConfigFileContents,
					dwNumberOfBytesRead,
					NULL,
					0);

				// Allocate the required number of bytes
				wchar_t* ConfigString_Converted = (wchar_t*)malloc(cchConfigFileString * sizeof(wchar_t));

				if (ConfigString_Converted == NULL) {
					if (ConfigFileContents != NULL) {
						free(ConfigFileContents);
						return FALSE;
					}
				}

				// Convert the contents
				int iResult = MultiByteToWideChar(CP_UTF8,
					MB_PRECOMPOSED,
					ConfigFileContents,
					dwNumberOfBytesRead,
					ConfigString_Converted,
					cchConfigFileString);

				// Check for error
				if (iResult == 0) {
					DWORD dwError = GetLastError();
					if (ConfigString_Converted != NULL) {
						free(ConfigString_Converted);
						ConfigString_Converted = NULL;
					}

					if (ConfigFileContents != NULL) {
						free(ConfigFileContents);
						ConfigFileContents = NULL;
					}

					return FALSE;
				}

				

				// Read the tokenized string from the config string
				int index = 0;
				wchar_t* nextToken = NULL;
				wchar_t* token = wcstok_s(ConfigString_Converted, L":", &nextToken);

				while (token != NULL) {
					switch (index) {
					case 0:
						StringCchCopy(VirusTotalApiKey, 128, token);
						break;
					case 1:
						int result = swscanf_s(token, L"%d", &QueryRate);
						if (result == 0 || result == EOF) {
							// If we can't successfully read in the query rate value, default to 1 lookup per minute
							QueryRate = 1;
						}
					}
					index++;
					token = wcstok_s(NULL, L":", &nextToken);
				}

				// Free the converted wide character config string
				if (ConfigString_Converted != NULL) {
					free(ConfigString_Converted);
					ConfigString_Converted = NULL;
				}
			}

			// Free the buffer that held the file contents
			if (ConfigFileContents != NULL) {
				free(ConfigFileContents);
				ConfigFileContents = NULL;
			}
		}

		CloseHandle(hFile);
		bSuccess = TRUE;
	}

	return bSuccess;
}

// Function to convert the binary hash value to human readable format;
// The provided buffer must be large enough to accommodate the requested hash format otherwise
// this function will return an error code
BOOL GetHashString(LONG nItemID, INT64 hashType, std::wstring *itemHash) {
	size_t bufSize = 0;
	DWORD dwOperation = 0x01; // Flag to XWF_GetHashValue; See https://www.x-ways.net/forensics/x-tensions/XWF_functions.html#A
	std::wstringstream ss;
	ss << std::hex;

	switch (hashType) {
	case XWF_HASHTYPE_MD5:
		bufSize = 16;
		break;
	case XWF_HASHTYPE_SHA1:
		bufSize = 20;
		break;
	case XWF_HASHTYPE_SHA256:
		bufSize = 32;
		break;
	default:
		return FALSE;		// Invalid
	}

	// Get the hash value
	BYTE* hashBuf = (BYTE*)malloc(bufSize);
	if (hashBuf == NULL) {
		return FALSE;
	}

	ZeroMemory(hashBuf, bufSize);
	memcpy(hashBuf, (const void*)&dwOperation, sizeof(DWORD)); // copy the operation to the buffer to tell X-Ways what we're doing
	if (!XWF_GetHashValue(nItemID, hashBuf)) {
		free(hashBuf);
		return FALSE;
	}

	// Convert to human readable string
	for (size_t n = 0; n < bufSize; ++n) {
		ss << std::setw(2) << std::setfill(L'0') << (unsigned int)hashBuf[n];
	}

	// Append the hash value to the itemHash parameter that was passed in
	itemHash->append(ss.str());

	// Free the hash buffer
	free(hashBuf);

	return TRUE;
}

BOOL ParseFileReport(char* VTJSON, LONG nItemID) {
	BOOL bResult = FALSE;
	cJSON* vtJSON = cJSON_Parse(VTJSON);
	cJSON* data = NULL;
	cJSON* attributes = NULL;
	cJSON* analysis_stats = NULL;
	cJSON* harmless = NULL;
	cJSON* suspicious = NULL;
	cJSON* malicious = NULL;
	cJSON* undetected = NULL;

	// Numerical values from the JSON
	int nHarmless = 0;
	int nSuspicious = 0;
	int nMalicious = 0;
	int nUndetected = 0;

	// Format string for the output that will be saved to the X-ways metadata field
	const wchar_t* szFormatString = L"[XT_VT]: Malicious: %d, Suspicious: %d, Undetected: %d, Harmless: %d";
	wchar_t* szOutputString = NULL;
	size_t cchOutputString = 0;

	if (vtJSON == NULL) {
		// Print an error message
		XWF_OutputMessage(L"Error parsing JSON response from VirusTotal.", 0);
		goto cleanup;
	} 

	data = cJSON_GetObjectItemCaseSensitive(vtJSON, "data");
	if (data == NULL) {
		XWF_OutputMessage(L"Error: Invalid data returned from VirusTotal. Expected object 'data' was not found.", 0);
		goto cleanup;
	}

	attributes = cJSON_GetObjectItemCaseSensitive(data, "attributes");
	if (attributes == NULL) {
		XWF_OutputMessage(L"Error: Invalid data returned from VirusTotal. Expected object 'attributes' was not found.", 0);
		goto cleanup;
	}

	analysis_stats = cJSON_GetObjectItemCaseSensitive(attributes, "last_analysis_stats");
	if (analysis_stats == NULL) {
		XWF_OutputMessage(L"Error: Invalid data returned from VirusTotal. Expected object 'last_analysis_stats' was not found.", 0);
		goto cleanup;
	}

	// Fields we are interested in are: harmless, suspicious, malicious, and undetected; values are integer
	harmless = cJSON_GetObjectItemCaseSensitive(analysis_stats, "harmless");
	if (harmless != NULL) {
		nHarmless = harmless->valueint;
	}

	suspicious = cJSON_GetObjectItemCaseSensitive(analysis_stats, "suspicious");
	if (suspicious != NULL) {
		nSuspicious = suspicious->valueint;
	}

	malicious = cJSON_GetObjectItemCaseSensitive(analysis_stats, "malicious");
	if (malicious != NULL) {
		nMalicious = malicious->valueint;
	}

	undetected = cJSON_GetObjectItemCaseSensitive(analysis_stats, "undetected");
	if (undetected != NULL) {
		nUndetected = undetected->valueint;
	}

	// Sanity checks
	if (nHarmless == 0 && nSuspicious == 0 && nMalicious == 0 && nUndetected == 0) {
		// No meaningful results came back from VT. Put out a message and do nothing.
	}

	if (nHarmless < 0 || nSuspicious < 0 || nMalicious < 0 || nUndetected < 0) {
		// One of the numbers was wildly out of range
	}

	// Virustotal only has ~70 scanners currently. 100 should give us a buffer for future additions
	if (nHarmless > 100 || nSuspicious > 100 || nMalicious > 100 || nUndetected > 100) {
		// One of the numbers was greater than expected
	}

	// Field width max = 3 (max 100 scanners)
	// Format string characters per field = 2
	// Number of fields = 4
	// Thus we add one character for each of the fields, for a total of 4 extra characters
	// Plus a terminating null character = 5 total extra characters we need in the buffer
	cchOutputString = wcslen(szFormatString) + 5; 

	// Allocate a buffer for the formatted data
	szOutputString = (wchar_t*)malloc(cchOutputString * sizeof(wchar_t));
	
	if (szOutputString == NULL) {
		// Memory allocation failed; write an error message and do nothing
		goto cleanup;
	}

	// Zero out the output string
	ZeroMemory(szOutputString, (cchOutputString * sizeof(wchar_t)));

	// Write the numerical data to the formatted string buffer
	StringCchPrintf(szOutputString, cchOutputString, szFormatString, nMalicious, nSuspicious, nUndetected, nHarmless);

	// Add the comment
	if (XWF_GetExtractedMetadata(nItemID) == NULL || wcsstr(XWF_GetExtractedMetadata(nItemID), L"[XT_VT]") == NULL) {
		XWF_AddExtractedMetadata(nItemID, szOutputString, 2);
		bResult = TRUE;
	}

	// If the a scanner has reported the file as malicious, use X-Ways internal API to flag the file as "known bad hash category"
	if (nMalicious > 0) {
		BOOL bSuccess = FALSE;
		INT64 iXwFlags = XWF_GetItemInformation(nItemID, XWF_ITEM_INFO_FLAGS, &bSuccess);
		if (bSuccess)
			XWF_SetItemInformation(nItemID, XWF_ITEM_INFO_FLAGS, iXwFlags | 0x00400000);
	}
cleanup:
	if (vtJSON != NULL) {
		cJSON_free(vtJSON);
	}

	if (data != NULL) {
		cJSON_free(data);
	}

	if (attributes != NULL) {
		cJSON_free(attributes);
	}

	if (analysis_stats != NULL) {
		cJSON_free(analysis_stats);
	}

	if (harmless != NULL) {
		cJSON_free(harmless);
	}

	if (suspicious != NULL) {
		cJSON_free(suspicious);
	}

	if (malicious != NULL) {
		cJSON_free(malicious);
	}

	if (undetected != NULL) {
		cJSON_free(undetected);
	}

	if (szOutputString != NULL) {
		free(szOutputString);
	}

	return bResult;
}