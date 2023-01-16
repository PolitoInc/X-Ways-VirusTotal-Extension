#pragma once
#define XT_PREPARE_CALLPI 0x01
#define XT_PREPARE_CALLPILATE 0x02
#define XT_PREPARE_EXPECTMOREITEMS 0x04
#define XT_PREPARE_DONTOMIT 0x08
#define XT_PREPARE_TARGETDIRS 0x10
#define XT_PREPARE_TARGETZEROBYTEFILES 0x20


#define XT_ACTION_RUN 0 // simply run directly from the main menu or command line3
#define XT_ACTION_RVS 1 // volume snapshot refinement starting2
#define XT_ACTION_LSS 2 // logical simultaneous search starting
#define XT_ACTION_PSS 3 // physical simultaneous search starting
#define XT_ACTION_DBC 4 // directory browser context menu command invoked1
#define XT_ACTION_SHC 5 // search hit list context menu command invoked
#define XT_ACTION_EVT 6 // event list context menu command invoked (since v20.3 SR-3)

#define XT_HASH1ALREADYCOMPUTED		0x40000		// Bit flag set if the first hash value has been computed
#define XT_HASH2ALREADYCOMPUTED		0x100000	// Bit flag set if the second hash value has been computed

#define XWF_VSPROP_HASHTYPE1	20	// Tells XWF_GetVSProp to retrieve the type for the first computed hash
#define XWF_VSPROP_HASHTYPE2	21	// Tells XWF_GetVSProp to retrieve the type for the second computed hash

#define XWF_HASHTYPE_MD5 7
#define XWF_HASHTYPE_SHA1 8
#define XWF_HASHTYPE_SHA256 9

#include <string>
#include <list>
#include <iomanip>
#include <sstream>

BOOL ReadAPIConfigFile(HMODULE hModule);
int GetHashString(LONG nItemID, INT64 hashType, std::wstring *itemHash);
BOOL ParseFileReport(char* VTJSON, LONG nItemID);
DWORD WINAPI QueueProcessingFunc(LPVOID lpParam);

typedef struct XWFITEMHASH {
	LONG nItemID;	// the XWF Item ID corresponding to this hash
	std::wstring szHash;
} XWFITEMHASH;