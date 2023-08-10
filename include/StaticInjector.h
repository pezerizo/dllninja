#pragma once

#include <windows.h>

#define MAXPATH 255

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
	
    char pe_name[MAXPATH];
	HANDLE file;
        LPVOID fileDataBegin;

		DWORD baseFileSize;
        LPVOID baseFileBegAddress;
        LPVOID baseFileEndAddress;

        DWORD editedFileSize;
        LPVOID editedFileBegAddress;
        LPVOID editedFileEndAddress;

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

        DWORD bufferPartSize;
        LPVOID bufferPartBegAddress;
        LPVOID bufferPartEndAddress;
};


class StaticInjector{
    public:
        StaticInjector();

        int LoadPE(const char* filename);
        void InjectDLL(const char* dllname);
        void EdjectDLL(const char* dllname);

    private:
        int SavePE();
        LPVOID _allocExtendMem();

        PEheaderData* pe_data;
};

StaticInjector::StaticInjector(){
    this->pe_data = new PEheaderData();
}


int StaticInjector::LoadPE(const char* filename){
    CopyMemory(&(this->pe_data->pe_name), filename, MAXPATH);

    pe_data->file = CreateFileA(&(this->pe_data->pe_name), GENERIC_ALL, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (pe_data->file == INVALID_HANDLE_VALUE) printf("Could not read file");
	
	_allocExtendMem();
	
	ReadFile(pe_data->file, pe_data->fileData, pe_data->baseFileSize, &(pe_data->bytesRead), NULL);
}

LPVOID StaticInjector::_allocExtendMem(){

	this->pe_data->baseFileSize = GetFileSize(this->pe_data->file, NULL);
	this->pe_data->extendedPartSize = 255;
	this->pe_data->extendedFileSize = (this->pe_data->baseFileSize + this->pe_data->extendedPartSize);
	this->pe_data->fileData = HeapAlloc(GetProcessHeap(), 0, this->pe_data->extendedFileSize);

    this->pe_data->baseFileBegAddress = this->pe_data->fileData;
	this->pe_data->baseFileEndAddress = (LPVOID)((DWORD)pe_data->fileData + (DWORD)pe_data->baseFileSize);
	this->pe_data->currentFileEndAddress = pe_data->baseFileEndAddress;

    this->pe_data->editedFileBegAddress = this->pe_data->baseFileBegAddress;
    this->pe_data->editedFileEndAddress = this->pe_data->baseFileEndAddress
    this->pe_data->editedFileSize = this->pe_data->baseFileSize;

	return pe_data->fileData;
}