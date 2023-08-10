#pragma once

#include <windows.h>

#if __GNUC__
#if __x86_64__ || __ppc64__
#define ENVIRONMENT64
#else
#define ENVIRONMENT32
#endif
#endif

struct PEheaderData{
	PIMAGE_DOS_HEADER dosHeader;
	
    #ifdef ENVIRONMENT32
	    PIMAGE_NT_HEADERS32 imageNTheaders;
    #else
        PIMAGE_NT_HEADERS64 imageNTheaders;
    #endif
		DWORD sign;
		PIMAGE_FILE_HEADER imgFileHeader;
        #ifdef ENVIRONMENT32
		    PIMAGE_OPTIONAL_HEADER32 imgOptHeader;
        #else
            PIMAGE_OPTIONAL_HEADER64 imgOptHeader;
        #endif

	IMAGE_DATA_DIRECTORY idataSectionAddress;
	PIMAGE_SECTION_HEADER idataSectionHeader;
	PIMAGE_SECTION_HEADER rdataSectionHeader;
	PIMAGE_SECTION_HEADER sectionHeader;

	IMAGE_IMPORT_DESCRIPTOR* importDescriptor;
		PIMAGE_THUNK_DATA INTdataThunk;
		PIMAGE_THUNK_DATA IATdataThunk;
	
	HANDLE file;
        LPVOID fileDataBegin;

		DWORD baseFileSize;
        LPVOID baseFileBegAddress;
        LPVOID baseFileEndAddress;

        LPVOID injectPointAddress;

        DWORD extendedFileSize;
        DWORD extendedPartSize;
        LPVOID extendedFileBegAddress;
        LPVOID extendedFileEndAddress;
        LPVOID extendedPartBegAddress;
        LPVOID extendedPartEndAddress;

        DWORD topPartSize;
        LPVOID topPartBegAddress;
        LPVOID topPartEndAddress;

        DWORD bottomPartSize;
        LPVOID bottomPartBegAddress;
        LPVOID bottomPartEndAddress;

        DWORD bytesReaded;
        DWORD bytesWrited;
}


class StaticInjector{
    public:
        StaticInjector() {}

        LoadPE(const char* filename);
        InjectDLL(const char* dllname);
        EdjectDLL(const char* dllname);

    private:
        SavePE();

        PEheaderData* pe_data;
}