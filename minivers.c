
#include "minivers.h"
#include <ntstrsafe.h>
#include "copy_file.h"
#include <io.h>

#pragma comment(lib,"kernel32.lib")

#pragma warning(disable:4995)

//#define access access
#define DEFERRED_IO            TRUE
#define IMMUTABLE_BACKUP_FILES TRUE
#define INVALID_FILE_ATTRIBUTES ((DWORD)-1)

#define BUFFER_SIZE (4 * 1024)

PFLT_PORT port = NULL;
PFLT_PORT ClientPort = NULL;

PCHAR processStatic = NULL;
PCHAR create = "create";
PCHAR rname = "rname";
PCHAR delete = "delete";

PKEVENT		pEvent = NULL;
HANDLE		gEventHandle;
#define		EVENT_NAME  L"\\BaseNamedObjects\\MzfFileMonEvent"
#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002
CHAR strPath1[260] = { 0 };
CHAR strPath2[260] = { 0 };
CHAR strPath3[260] = { 0 };
CHAR strPath[780] = { 0 };

INT FileExit;
PCHAR PathPattern;
PCHAR Pathinfo;
PCHAR PatRecycle = "Recycle";
PCHAR CopyStatus;

DWORD dwAttr;
ANSI_STRING ansi = { 0 };
CHAR ansiBuf[256] = { 0 };

ANSI_STRING ansirename = { 0 };
CHAR ansirenameBuf[256] = { 0 };

PCHAR exisitsFile;
PCHAR sprit = "\\";

UNICODE_STRING filerename;
UNICODE_STRING string;
INT renamePat = 1;
PCHAR renamepath;
UNICODE_STRING oldPath;

static DRIVER_DATA driver_data;

static DWORD GetFileAttributes(LPCTSTR lpFileName);
/*
BOOLEAN IsFileExist(LPCTSTR lpFileName){
	if (lpFileName)
		return FALSE;
	dwAttr = GetFileAttributes(lpFileName);
	if (INVALID_FILE_ATTRIBUTES == dwAttr || (dwAttr & FILE_ATTRIBUTE_DIRECTORY))
		return FALSE;
	return TRUE;
}*/

/******************************************************************************
 ******************************************************************************
 **                                                                          **
 ** File extensions to be taken into account.                                **
 **                                                                          **
 ******************************************************************************
 ******************************************************************************/
DECLARE_CONST_UNICODE_STRING(DOC, L"doc");
DECLARE_CONST_UNICODE_STRING(DOCX, L"docx");
DECLARE_CONST_UNICODE_STRING(XLS, L"xls");
DECLARE_CONST_UNICODE_STRING(XLSX, L"xlsx");
DECLARE_CONST_UNICODE_STRING(TXT, L"txt");
DECLARE_CONST_UNICODE_STRING(PPT, L"ppt");
DECLARE_CONST_UNICODE_STRING(PPTX, L"pptx");
DECLARE_CONST_UNICODE_STRING(HWP, L"hwp");

static const UNICODE_STRING* extensions[] = { &DOC, &DOCX, &XLS, &XLSX, &TXT };


/******************************************************************************
 ******************************************************************************
 **                                                                          **
 ** minivers's file extension.                                               **
 **                                                                          **
 ******************************************************************************
 ******************************************************************************/
DECLARE_CONST_UNICODE_STRING(MINIVERS_EXT, L"minivers");
DECLARE_CONST_UNICODE_STRING(PATHBEH, L".*.minivers");


DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath);

static NTSTATUS process_irp(PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID* CompletionContext,
	BOOLEAN deferred_io);

static BOOLEAN get_file_name_information(PFLT_CALLBACK_DATA data,
	PFLT_FILE_NAME_INFORMATION* name_info);

static BOOLEAN find_extension(const UNICODE_STRING* ext);
static BOOLEAN duplicate_file(PFLT_CALLBACK_DATA CallbackData,
	PFLT_INSTANCE instance);

static void deferred_io_workitem(PFLT_DEFERRED_IO_WORKITEM FltWorkItem,
	PFLT_CALLBACK_DATA CallbackData,
	PVOID Context);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, InstanceSetup)
#pragma alloc_text(PAGE, FilterUnload)
#pragma alloc_text(PAGE, InstanceQueryTeardown)
#endif /* ALLOC_PRAGMA */


NTSTATUS MiniConnect(PFLT_PORT clientport, PVOID serverportcookie, PVOID Context, ULONG size, PVOID Connectioncookie)
{
	UNREFERENCED_PARAMETER(Connectioncookie);
	UNREFERENCED_PARAMETER(size);
	UNREFERENCED_PARAMETER(Context);
	UNREFERENCED_PARAMETER(serverportcookie);

	ClientPort = clientport;
	DbgPrint("connect \r\n");
	return STATUS_SUCCESS;
}

VOID MiniDisconnect(PVOID connectioncookie)
{
	UNREFERENCED_PARAMETER(connectioncookie);

	DbgPrint("disconnect \r\n");
	FltCloseClientPort(driver_data.filter, &ClientPort);
}

NTSTATUS MiniSendRec(PVOID portcookie, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG RetLength)
{
	UNREFERENCED_PARAMETER(RetLength);
	UNREFERENCED_PARAMETER(OutputBufferLength);
	UNREFERENCED_PARAMETER(InputBufferLength);
	UNREFERENCED_PARAMETER(portcookie);

//	msg = "kernel msg";
//	DbgPrint("user msg is : %s \r\n", (PCHAR)InputBuffer);

	_try{

		strcpy(strPath, strPath1);
		strcat(strPath, strPath2);
		strcat(strPath, strPath3);
		strcpy(OutputBuffer, strPath);
		DbgPrint("'%wS'", strPath);
		memset(strPath, 0, sizeof(strPath));
		memset(strPath1, 0, sizeof(strPath1));
		memset(strPath2, 0, sizeof(strPath2));
		memset(strPath3, 0, sizeof(strPath3));
	}
	_except(EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("catch error\r\n");
	}

	KeClearEvent(pEvent);

//	strcpy((PCHAR)OutputBuffer, msg);
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;
	PSECURITY_DESCRIPTOR sd;
	OBJECT_ATTRIBUTES oa = { 0 };
	UNICODE_STRING name = RTL_CONSTANT_STRING(L"\\NPMiniPort");
	UNICODE_STRING uniEventName;

	UNREFERENCED_PARAMETER(RegistryPath);

	/* Register with the filter manager. */
	status = FltRegisterFilter(DriverObject,
		&filter_registration,
		&driver_data.filter);

	if (!NT_SUCCESS(status)) {
		return status;
	}

	status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
	if (NT_SUCCESS(status)){

		InitializeObjectAttributes(&oa, &name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);
		status = FltCreateCommunicationPort(driver_data.filter, &port, &oa, NULL, MiniConnect, MiniDisconnect, MiniSendRec, 1);

		FltFreeSecurityDescriptor(sd);

		RtlInitUnicodeString(&uniEventName, EVENT_NAME);
		pEvent = IoCreateNotificationEvent(&uniEventName, &gEventHandle);
		if (pEvent != NULL)
		{
			KeClearEvent(pEvent);
		}

		if (NT_SUCCESS(status)){
			/* Start filtering. */
			status = FltStartFiltering(driver_data.filter);

			if (NT_SUCCESS(status)) {

				return status;

			}
			FltCloseCommunicationPort(port);
		}
		FltUnregisterFilter(driver_data.filter);
	}
	return status;
}

NTSTATUS InstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
	_In_ DEVICE_TYPE VolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(VolumeFilesystemType);

	PAGED_CODE();

	return (VolumeDeviceType != FILE_DEVICE_CD_ROM_FILE_SYSTEM) ?
	STATUS_SUCCESS :
				   STATUS_FLT_DO_NOT_ATTACH;
}

NTSTATUS FilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	FltCloseCommunicationPort(port);
	FltUnregisterFilter(driver_data.filter);

	return STATUS_SUCCESS;
}

NTSTATUS InstanceQueryTeardown(_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	return STATUS_SUCCESS;
}

PFILE_RENAME_INFORMATION renameInfo;

FLT_PREOP_CALLBACK_STATUS
PreOperationCallback(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
	/* IRP-based I/O operation? */
	if (FLT_IS_IRP_OPERATION(Data)) {
		/* Open file? */
		if (Data->Iopb->MajorFunction == IRP_MJ_CREATE) {
			/* Open file for writing/appending? */
			if (Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess &
				(FILE_WRITE_DATA | FILE_APPEND_DATA)) {
				processStatic = create;
				return process_irp(Data, FltObjects, CompletionContext, DEFERRED_IO);
			}
		}
		else if (Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION) {
			switch (Data->Iopb->Parameters.SetFileInformation.FileInformationClass) {
			case FileDispositionInformation:
				if (((FILE_DISPOSITION_INFORMATION*)
					Data->Iopb->Parameters.SetFileInformation.InfoBuffer
					)->DeleteFile) {
					processStatic = delete;
					return process_irp(Data, FltObjects, CompletionContext, FALSE);
				}

				break;

			case FileEndOfFileInformation:
			case FileRenameInformation:

				/* the renamed name */
				if (Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION){
					if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformation){
						renameInfo = (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
					}
				}

				processStatic = rname;
				return process_irp(Data, FltObjects, CompletionContext, FALSE);
			}
		}
	}

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

NTSTATUS process_irp(PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID* CompletionContext,
	BOOLEAN deferred_io)
{
	PFLT_FILE_NAME_INFORMATION name_info;
	PFLT_DEFERRED_IO_WORKITEM work;

	/* Get name information. */
	if (get_file_name_information(Data, &name_info)) {
		if (find_extension(&name_info->Extension)) {

			RtlInitEmptyAnsiString(&ansi, ansiBuf, 256 * sizeof(CHAR));
			RtlUnicodeStringToAnsiString(&ansi, &name_info->Name, TRUE);

			Pathinfo = ansi.Buffer;

			if (processStatic == create){

				DbgPrint("Create: '%wZ', extension: '%wZ'.",
					&name_info->Name,
					&name_info->Extension);

				const char *str1 = "FILE_CREATED:";
				const char *str2 = "^";

				strcpy(strPath2, str1);
				strcat(strPath2, ansi.Buffer);
				strcat(strPath2, str2);
				strPath2[ansi.Length + strlen(str1) + strlen(str2)] = 0;

				KeSetEvent(pEvent, IO_NO_INCREMENT, FALSE);
				KeClearEvent(pEvent);
				
				RtlFreeAnsiString(&ansi);

			}
			else if (processStatic == rname){
				DbgPrint("Rename: '%wZ', extension: '%wZ'.",
					&name_info->Name,
					&name_info->Extension);

//				renamePat = 0;

				/* get rename path */
//				WCHAR stringBuffer[BUFFER_SIZE];
				
//				string.Buffer = stringBuffer;
//				string.Length = 0x0;
//				string.MaximumLength = sizeof(stringBuffer);

//				RtlInitUnicodeString(&string, (PCWSTR)&renameInfo->FileName);

				const char *str1 = "FILE_RENAME:";
				const char *str2 = "^";

				strcpy(strPath3, str1);
				strcat(strPath3, ansi.Buffer);
				strcat(strPath3, str2);
				strPath3[ansi.Length + strlen(str1) + strlen(str2)] = 0;

				KeSetEvent(pEvent, IO_NO_INCREMENT, FALSE);
				KeClearEvent(pEvent);

				RtlFreeAnsiString(&ansi);

			}
			else if (processStatic == delete){
				DbgPrint("Delete: '%wZ', extension: '%wZ'.",
					&name_info->Name,
					&name_info->Extension);

				const char *str1 = "FILE_DELETED:";
				const char *str2 = "^";

				strcpy(strPath1, str1);
				strcat(strPath1, ansi.Buffer);
				strcat(strPath1, str2);
				strPath1[ansi.Length + strlen(str1) + strlen(str2)] = 0;

				KeSetEvent(pEvent, IO_NO_INCREMENT, FALSE);
				KeClearEvent(pEvent);

				RtlFreeAnsiString(&ansi);

			}
			else{
				DbgPrint("Filename: '%wZ', extension: '%wZ'.",
					&name_info->Name,
					&name_info->Extension);
			}

			if (deferred_io) {
				if ((work = FltAllocateDeferredIoWorkItem()) != NULL) {
					if (NT_SUCCESS(FltQueueDeferredIoWorkItem(
						work,
						Data,
						deferred_io_workitem,
						DelayedWorkQueue,
						FltObjects->Instance
						))) {
						FltReleaseFileNameInformation(name_info);

						*CompletionContext = NULL;

						return FLT_PREOP_PENDING;
					}
					else {
						FltFreeDeferredIoWorkItem(work);
					}
				}
			}

			duplicate_file(Data, FltObjects->Instance);
#if IMMUTABLE_BACKUP_FILES
		}
		else if (RtlEqualUnicodeString(&name_info->Extension,
			&MINIVERS_EXT,
			TRUE)) {
			DbgPrint("Filename: '%wZ', extension: '%wZ'.",
				&name_info->Name,
				&name_info->Extension);

			FltReleaseFileNameInformation(name_info);

			Data->IoStatus.Status = STATUS_ACCESS_DENIED;
			return FLT_PREOP_COMPLETE;
#endif /* IMMUTABLE_BACKUP_FILES */
		}

		FltReleaseFileNameInformation(name_info);
	}

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

BOOLEAN get_file_name_information(PFLT_CALLBACK_DATA data,
	PFLT_FILE_NAME_INFORMATION* name_info)
{
	/* Get name information. */
	if (NT_SUCCESS(FltGetFileNameInformation(
		data,
		FLT_FILE_NAME_NORMALIZED |
		FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
		name_info
		))) {
		/* Parse file name information. */
		if (NT_SUCCESS(FltParseFileNameInformation(*name_info))) {
			return TRUE;
		}

		FltReleaseFileNameInformation(*name_info);
#if OSVER(NTDDI_VERSION) > NTDDI_WIN2K
	}
	else {
		/*
		 * We couldn't get the "normalized" name, try to get the "opened"
		 * name.
		 */
		if (NT_SUCCESS(FltGetFileNameInformation(data,
			FLT_FILE_NAME_OPENED |
			FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
			name_info
			))) {
			if (NT_SUCCESS(FltParseFileNameInformation(*name_info))) {
				return TRUE;
			}

			FltReleaseFileNameInformation(*name_info);
		}
#endif /* OSVER(NTDDI_VERSION) > NTDDI_WIN2K */
	}

	return FALSE;
}


BOOLEAN find_extension(const UNICODE_STRING* ext)
{
	size_t i;

	for (i = 0; i < ARRAYSIZE(extensions); i++) {
		if (RtlEqualUnicodeString(ext, extensions[i], TRUE)) {
			return TRUE;
		}
	}

	return FALSE;
}


BOOLEAN duplicate_file(PFLT_CALLBACK_DATA CallbackData, PFLT_INSTANCE instance)
{
	PFLT_FILE_NAME_INFORMATION name_info;
	UNICODE_STRING dest;
	LARGE_INTEGER system_time, local_time;
	TIME_FIELDS time;

	/* delete file */
	OBJECT_ATTRIBUTES attr;
	UNICODE_STRING delpath;
	UNICODE_STRING PathPattern;

	/****** delect file ***/
	
	UNICODE_STRING dir;
	/**********************/


	/* Get name information. */
	if (get_file_name_information(CallbackData, &name_info)) {
		/* Compute size in bytes.
		 * Suffix's format: .YYYYMMDD_hhmmss_mmm.<MINIVERS_EXT>
		 */
		dest.MaximumLength = name_info->Name.Length +
			42 +
			MINIVERS_EXT.Length +
			sizeof(WCHAR);

		/* Allocate memory for the destination file name. */
		if ((dest.Buffer = ExAllocatePoolWithTag(NonPagedPool,
			dest.MaximumLength,
			TAG)) != NULL) {
			dest.Length = 0;

			/* Get system time. */
			KeQuerySystemTime(&system_time);

			/* Convert system time to local time. */
			ExSystemTimeToLocalTime(&system_time, &local_time);

			RtlTimeToTimeFields(&local_time, &time);

			/* Compose name of the new file. */
			/*
			if (NT_SUCCESS(RtlUnicodeStringPrintf(
				&dest,
				L"%wZ.%04u%02u%02u_%02u%02u%02u_%03u.%wZ",
				&name_info->Name,
				time.Year,
				time.Month,
				time.Day,
				time.Hour,
				time.Minute,
				time.Second,
				time.Milliseconds,
				&MINIVERS_EXT
				))) {
				*/

//			RtlInitEmptyAnsiString(&ansirename, ansirenameBuf, 256 * sizeof(CHAR));
//			RtlUnicodeStringToAnsiString(&ansirename, &name_info->Name, TRUE);

//			WCHAR stringBuffer[BUFFER_SIZE];

//			oldPath.Buffer = stringBuffer;
//			oldPath.Length = 0x0;
//			oldPath.MaximumLength = sizeof(stringBuffer);

//			RtlInitUnicodeString(&oldPath, (PCWSTR)ansirename.Buffer);

//			oldPath = name_info->Name;

			/* 0 = rename, 1 = no rename, The default is 1 */
//			if (renamePat == 0){

//			}

			if (NT_SUCCESS(RtlUnicodeStringPrintf(
				&dest,
				L"%wZ.%wZ",
				&name_info->Name,
				&MINIVERS_EXT
				))) {

				/****************
				 **            **  
				 ** Copy file. **
				 **            **
				 ****************/

				/* unicodestring to pchar */
				
				RtlInitEmptyAnsiString(&ansi, ansiBuf, 256 * sizeof(CHAR));
				RtlUnicodeStringToAnsiString(&ansi, &name_info->Name, TRUE);

				Pathinfo = ansi.Buffer;
				CopyStatus = strstr(Pathinfo, PatRecycle);
				

//				RtlUnicodeStringPrintf(&delpath, L"%wZ.%wZ", &name_info->Name, &PATHBEH);


				if (CopyStatus == NULL){

//					PathPattern = strcat(Pathinfo, ".*.minivers");

					/* zwdeletefile funtion */

//					dir_query(driver_data.filter, instance, &dir);

//					RtlInitUnicodeString(*delpath, PathPattern);

//					InitializeObjectAttributes(&attr, 
//						&delpath, 
//						OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 
//						NULL, 
//						NULL);
//					ZwDeleteFile(&attr);
//					RtlFreeUnicodeString(&delpath);
					
					/* access funtion */
//					FileExit = _access(PathPattern, 0);

					/* stat funtion */
//					struct stat   buffile;
//					FileExit = stat(PathPattern, &buffile);

					/* fopen funtion */
//					FileExit = existfile(PathPattern);
					

//					FileExit = CheckExistsFile((PUNICODE_STRING)PathPattern);

//					if (FileExit){

//						DbgPrint("Exists:*****************************************");

//					}

					if (copy_file(driver_data.filter, instance, &dest, &name_info->Name)) {
						ExFreePoolWithTag(dest.Buffer, TAG);
						FltReleaseFileNameInformation(name_info);

						return TRUE;
					}
				}
			}

			ExFreePoolWithTag(dest.Buffer, TAG);
		}

		FltReleaseFileNameInformation(name_info);
	}

	return FALSE;
}

void deferred_io_workitem(PFLT_DEFERRED_IO_WORKITEM FltWorkItem,
	PFLT_CALLBACK_DATA CallbackData,
	PVOID Context)
{
	duplicate_file(CallbackData, Context);

	FltFreeDeferredIoWorkItem(FltWorkItem);

	FltCompletePendedPreOperation(CallbackData,
		FLT_PREOP_SUCCESS_NO_CALLBACK,
		NULL);
}
