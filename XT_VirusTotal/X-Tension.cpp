///////////////////////////////////////////////////////////////////////////////
// X-Tension API - Implementation of XT_RetrieveFunctionPointers
// Copyright X-Ways Software Technology AG
///////////////////////////////////////////////////////////////////////////////

#include "pch.h"
#include "X-Tension.h"
//#include "BGStringTemplates.h"


// Please consult
// http://x-ways.com/forensics/x-tensions/api.html
// for current documentation

//fptr_XWF_GetSize XWF_GetSize;

///////////////////////////////////////////////////////////////////////////////
// Variables that store the function pointers

fptr_XWF_GetSize XWF_GetSize;
fptr_XWF_GetVolumeName XWF_GetVolumeName;
fptr_XWF_GetVolumeInformation XWF_GetVolumeInformation;
fptr_XWF_GetSectorContents XWF_GetSectorContents;
fptr_XWF_Read XWF_Read;
fptr_XWF_SectorIO XWF_SectorIO;
fptr_XWF_SelectVolumeSnapshot XWF_SelectVolumeSnapshot;
fptr_XWF_GetVSProp XWF_GetVSProp;
fptr_XWF_GetItemCount XWF_GetItemCount;
fptr_XWF_GetFileCount XWF_GetFileCount;
fptr_XWF_CreateItem XWF_CreateItem;
fptr_XWF_CreateFile XWF_CreateFile;
fptr_XWF_FindItem1 XWF_FindItem1;
fptr_XWF_GetItemName XWF_GetItemName;
fptr_XWF_GetItemSize XWF_GetItemSize;
fptr_XWF_SetItemSize XWF_SetItemSize;
fptr_XWF_GetItemOfs XWF_GetItemOfs;
fptr_XWF_SetItemOfs XWF_SetItemOfs;
fptr_XWF_GetItemInformation XWF_GetItemInformation;
fptr_XWF_SetItemInformation XWF_SetItemInformation;
fptr_XWF_GetItemType XWF_GetItemType;
fptr_XWF_SetItemType XWF_SetItemType;
fptr_XWF_GetItemParent XWF_GetItemParent;
fptr_XWF_SetItemParent XWF_SetItemParent;
fptr_XWF_GetHashSetAssocs XWF_GetHashSetAssocs;
fptr_XWF_GetReportTableAssocs XWF_GetReportTableAssocs;
fptr_XWF_AddToReportTable XWF_AddToReportTable;
fptr_XWF_GetComment XWF_GetComment;
fptr_XWF_AddComment XWF_AddComment;
fptr_XWF_OutputMessage XWF_OutputMessage;
fptr_XWF_GetUserInput XWF_GetUserInput;
fptr_XWF_ShowProgress XWF_ShowProgress;
fptr_XWF_SetProgressPercentage XWF_SetProgressPercentage;
fptr_XWF_SetProgressDescription XWF_SetProgressDescription;
fptr_XWF_ShouldStop XWF_ShouldStop;
fptr_XWF_HideProgress XWF_HideProgress;
fptr_XWF_ReleaseMem XWF_ReleaseMem;

fptr_XWF_GetBlock XWF_GetBlock;
fptr_XWF_SetBlock XWF_SetBlock;
fptr_XWF_GetCaseProp XWF_GetCaseProp;
fptr_XWF_GetFirstEvObj XWF_GetFirstEvObj;
fptr_XWF_GetNextEvObj XWF_GetNextEvObj;
fptr_XWF_OpenEvObj XWF_OpenEvObj;
fptr_XWF_CloseEvObj XWF_CloseEvObj;
fptr_XWF_GetEvObj XWF_GetEvObj;
fptr_XWF_GetEvObjProp XWF_GetEvObjProp;
fptr_XWF_GetExtractedMetadata XWF_GetExtractedMetadata;
fptr_XWF_GetMetadataEx XWF_GetMetadataEx;
fptr_XWF_GetRasterImage XWF_GetRasterImage;
fptr_XWF_AddExtractedMetadata XWF_AddExtractedMetadata;
fptr_XWF_GetHashValue XWF_GetHashValue;
fptr_XWF_SetHashValue XWF_SetHashValue;
fptr_XWF_AddEvent XWF_AddEvent;
fptr_XWF_GetEvent XWF_GetEvent;
fptr_XWF_GetReportTableInfo XWF_GetReportTableInfo;
fptr_XWF_GetEvObjReportTableAssocs XWF_GetEvObjReportTableAssocs;

// Search-Related Functions
fptr_XWF_Search XWF_Search;
fptr_XWF_AddSearchTerm XWF_AddSearchTerm;
fptr_XWF_GetSearchTerm XWF_GetSearchTerm;

fptr_XWF_GetWindow XWF_GetWindow;
fptr_XWF_GetProp XWF_GetProp;
fptr_XWF_ManageSearchTerm XWF_ManageSearchTerm;

///////////////////////////////////////////////////////////////////////////////
// XT_RetrieveFunctionPointers - call this function before calling anything else

LONG missingFunctionCount;

void* getFunction(HMODULE Hdl, const char* functionName)
{
	void* result = GetProcAddress(Hdl, functionName);

	if (result == NULL) {
		++missingFunctionCount;
	}

	return result;
}

// Retrieves the function pointers into XWF and returns the number of missing functions
LONG __stdcall XT_RetrieveFunctionPointers()
{
	HMODULE Hdl = GetModuleHandle(NULL);
	missingFunctionCount = 0;

	XWF_GetSize = (fptr_XWF_GetSize) getFunction(Hdl, "XWF_GetSize");
	XWF_GetVolumeName = (fptr_XWF_GetVolumeName) getFunction(Hdl, "XWF_GetVolumeName");
	XWF_GetVolumeInformation = (fptr_XWF_GetVolumeInformation) getFunction(Hdl, "XWF_GetVolumeInformation");
	XWF_GetSectorContents = (fptr_XWF_GetSectorContents) getFunction(Hdl, "XWF_GetSectorContents");
	XWF_Read = (fptr_XWF_Read) getFunction(Hdl, "XWF_Read");
	XWF_SectorIO = (fptr_XWF_SectorIO) getFunction(Hdl, "XWF_SectorIO");

	XWF_SelectVolumeSnapshot = (fptr_XWF_SelectVolumeSnapshot) getFunction(Hdl, "XWF_SelectVolumeSnapshot");
	XWF_GetVSProp = (fptr_XWF_GetVSProp) getFunction(Hdl, "XWF_GetVSProp");
	XWF_GetItemCount = (fptr_XWF_GetItemCount) getFunction(Hdl, "XWF_GetItemCount");
	XWF_GetFileCount = (fptr_XWF_GetFileCount) getFunction(Hdl, "XWF_GetFileCount");
	XWF_CreateFile = (fptr_XWF_CreateFile) getFunction(Hdl, "XWF_CreateFile");
	XWF_FindItem1 = (fptr_XWF_FindItem1) getFunction(Hdl, "XWF_FindItem1");

	XWF_CreateItem = (fptr_XWF_CreateItem) getFunction(Hdl, "XWF_CreateItem");
	XWF_GetItemName = (fptr_XWF_GetItemName) getFunction(Hdl, "XWF_GetItemName");
	XWF_GetItemSize = (fptr_XWF_GetItemSize) getFunction(Hdl, "XWF_GetItemSize");
	XWF_SetItemSize = (fptr_XWF_SetItemSize) getFunction(Hdl, "XWF_SetItemSize");
	XWF_GetItemOfs = (fptr_XWF_GetItemOfs) getFunction(Hdl, "XWF_GetItemOfs");
	XWF_SetItemOfs = (fptr_XWF_SetItemOfs) getFunction(Hdl, "XWF_SetItemOfs");
	XWF_GetItemInformation = (fptr_XWF_GetItemInformation) getFunction(Hdl, "XWF_GetItemInformation");
	XWF_SetItemInformation = (fptr_XWF_SetItemInformation) getFunction(Hdl, "XWF_SetItemInformation");
	XWF_GetItemType = (fptr_XWF_GetItemType) getFunction(Hdl, "XWF_GetItemType");
	XWF_SetItemType = (fptr_XWF_SetItemType) getFunction(Hdl, "XWF_SetItemType");
	XWF_GetItemParent = (fptr_XWF_GetItemParent) getFunction(Hdl, "XWF_GetItemParent");
	XWF_SetItemParent = (fptr_XWF_SetItemParent) getFunction(Hdl, "XWF_SetItemParent");
	XWF_GetHashSetAssocs = (fptr_XWF_GetHashSetAssocs) getFunction(Hdl, "XWF_GetHashSetAssocs");
	XWF_GetReportTableAssocs = (fptr_XWF_GetReportTableAssocs) getFunction(Hdl, "XWF_GetReportTableAssocs");
	XWF_AddToReportTable = (fptr_XWF_AddToReportTable) getFunction(Hdl, "XWF_AddToReportTable");
	XWF_GetComment = (fptr_XWF_GetComment) getFunction(Hdl, "XWF_GetComment");
	XWF_AddComment = (fptr_XWF_AddComment) getFunction(Hdl, "XWF_AddComment");

	XWF_OutputMessage = (fptr_XWF_OutputMessage) getFunction(Hdl, "XWF_OutputMessage");
	XWF_GetUserInput = (fptr_XWF_GetUserInput) getFunction(Hdl, "XWF_GetUserInput");
	XWF_ShowProgress = (fptr_XWF_ShowProgress) getFunction(Hdl, "XWF_ShowProgress");
	XWF_SetProgressPercentage = (fptr_XWF_SetProgressPercentage) getFunction(Hdl, "XWF_SetProgressPercentage");
	XWF_SetProgressDescription = (fptr_XWF_SetProgressDescription) getFunction(Hdl, "XWF_SetProgressDescription");
	XWF_ShouldStop = (fptr_XWF_ShouldStop) getFunction(Hdl, "XWF_ShouldStop");
	XWF_HideProgress = (fptr_XWF_HideProgress) getFunction(Hdl, "XWF_HideProgress");
	XWF_ReleaseMem = (fptr_XWF_ReleaseMem) getFunction(Hdl, "XWF_ReleaseMem");

	XWF_GetBlock = (fptr_XWF_GetBlock) getFunction(Hdl, "XWF_GetBlock");
	XWF_SetBlock = (fptr_XWF_SetBlock) getFunction(Hdl, "XWF_SetBlock");
	XWF_GetCaseProp = (fptr_XWF_GetCaseProp) getFunction(Hdl, "XWF_GetCaseProp");
	XWF_GetFirstEvObj = (fptr_XWF_GetFirstEvObj) getFunction(Hdl, "XWF_GetFirstEvObj");
	XWF_GetNextEvObj = (fptr_XWF_GetNextEvObj) getFunction(Hdl, "XWF_GetNextEvObj");
	XWF_OpenEvObj = (fptr_XWF_OpenEvObj) getFunction(Hdl, "XWF_OpenEvObj");
	XWF_CloseEvObj = (fptr_XWF_CloseEvObj) getFunction(Hdl, "XWF_CloseEvObj");
	XWF_GetEvObj = (fptr_XWF_GetEvObj) getFunction(Hdl, "XWF_GetEvObj");
	XWF_GetEvObjProp = (fptr_XWF_GetEvObjProp) getFunction(Hdl, "XWF_GetEvObjProp");
	XWF_GetExtractedMetadata = (fptr_XWF_GetExtractedMetadata) getFunction(Hdl, "XWF_GetExtractedMetadata");
	XWF_GetMetadataEx = (fptr_XWF_GetMetadataEx) getFunction(Hdl, "XWF_GetMetadataEx");
	XWF_GetRasterImage = (fptr_XWF_GetRasterImage) getFunction(Hdl, "XWF_GetRasterImage");
	XWF_AddExtractedMetadata = (fptr_XWF_AddExtractedMetadata) getFunction(Hdl, "XWF_AddExtractedMetadata");
	XWF_GetHashValue = (fptr_XWF_GetHashValue) getFunction(Hdl, "XWF_GetHashValue");
	XWF_SetHashValue = (fptr_XWF_SetHashValue) getFunction(Hdl, "XWF_SetHashValue");
	XWF_AddEvent = (fptr_XWF_AddEvent) getFunction(Hdl, "XWF_AddEvent");
	XWF_GetEvent = (fptr_XWF_GetEvent) getFunction(Hdl, "XWF_GetEvent");
	XWF_GetReportTableInfo = (fptr_XWF_GetReportTableInfo) getFunction(Hdl, "XWF_GetReportTableInfo");
	XWF_GetEvObjReportTableAssocs = (fptr_XWF_GetEvObjReportTableAssocs) getFunction(Hdl, "XWF_GetEvObjReportTableAssocs");

	XWF_Search = (fptr_XWF_Search) getFunction(Hdl, "XWF_Search");
	XWF_AddSearchTerm = (fptr_XWF_AddSearchTerm) getFunction(Hdl, "XWF_AddSearchTerm");
	XWF_GetSearchTerm = (fptr_XWF_GetSearchTerm) getFunction(Hdl, "XWF_GetSearchTerm");

	XWF_GetWindow = (fptr_XWF_GetWindow) getFunction(Hdl, "XWF_GetWindow");
	XWF_GetProp = (fptr_XWF_GetProp) getFunction(Hdl, "XWF_GetProp");
	XWF_ManageSearchTerm = (fptr_XWF_ManageSearchTerm) getFunction(Hdl, "XWF_ManageSearchTerm");

	return missingFunctionCount;
}

