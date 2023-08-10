#pragma once

#include <windows.h>
#include <string>

#define MAXPATH 255

#if __GNUC__
#if __x86_64__ || __ppc64__
#define ENVIRONMENT64
#else
#define ENVIRONMENT32
#endif
#endif

#ifdef ENVIRONMENT32
	#define PIMAGE_NT_HEADERS32 PIMAGE_NT_HEADERS;
    #define PIMAGE_OPTIONAL_HEADER32 PIMAGE_OPTIONAL_HEADER;
#else
    #define PIMAGE_NT_HEADERS64 PIMAGE_NT_HEADERS;
    #define PIMAGE_OPTIONAL_HEADER64 PIMAGE_OPTIONAL_HEADER;
#endif

struct PEheaderData{
	PIMAGE_DOS_HEADER dosHeader;
	PIMAGE_NT_HEADERS imageNTheaders;

	DWORD sign;
	PIMAGE_FILE_HEADER imgFileHeader;
	PIMAGE_OPTIONAL_HEADER imgOptHeader;

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
        //void EdjectDLL(const char* dllname);

    private:
        LPVOID _allocExtendMem();
        LPVOID _injectData(DWORD rdataPointRVA, LPVOID data, DWORD size);

        PEheaderData* pe_data;
        DWORD extendBy;
};

StaticInjector::StaticInjector(DWORD extendBy){
    this->pe_data = new PEheaderData();
    this->extendBy = extendBy;
}


int StaticInjector::LoadPE(const char* filename){
    CopyMemory(&(this->pe_data->pe_name), filename, MAXPATH);

    pe_data->file = CreateFile((LPCSTR)&(this->pe_data->pe_name), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (pe_data->file == INVALID_HANDLE_VALUE) printf("Could not read file");
	
	_allocExtendMem();
	
	ReadFile(pe_data->file, pe_data->fileDataBegin, pe_data->baseFileSize, &(pe_data->bytesReaded), NULL);
}


LPVOID StaticInjector::_allocExtendMem(){

	this->pe_data->baseFileSize = GetFileSize(this->pe_data->file, NULL);
	this->pe_data->extendedPartSize = this->extendBy;
	this->pe_data->extendedFileSize = (this->pe_data->baseFileSize + this->pe_data->extendedPartSize);

	this->pe_data->fileDataBegin = HeapAlloc(GetProcessHeap(), 0, this->pe_data->extendedFileSize);

    this->pe_data->baseFileBegAddress = this->pe_data->fileDataBegin;
	this->pe_data->baseFileEndAddress = (LPVOID)((DWORD)pe_data->fileDataBegin + (DWORD)pe_data->baseFileSize);

    this->pe_data->editedFileBegAddress = this->pe_data->baseFileBegAddress;
    this->pe_data->editedFileEndAddress = this->pe_data->baseFileEndAddress;
    this->pe_data->editedFileSize = this->pe_data->baseFileSize;

    this->pe_data->extendedFileBegAddress = this->pe_data->baseFileEndAddress;
    this->pe_data->extendedFileEndAddress = (LPVOID)((DWORD)this->pe_data->extendedFileBegAddress + (DWORD)this->pe_data->extendedPartSize); 

	return pe_data->fileDataBegin;
}


void StaticInjector::InjectDLL(const char* dllname){
    this->pe_data->dosHeader = (PIMAGE_DOS_HEADER)(this->pe_data->fileDataBegin);
	this->pe_data->imageNTheaders = (PIMAGE_NT_HEADERS)((DWORD)this->pe_data->fileDataBegin + (DWORD)this->pe_data->dosHeader->e_lfanew);

	//pe_data->sign = (DWORD0)(*(pe_data->imageNTHeaders));
	this->pe_data->imgFileHeader = (PIMAGE_FILE_HEADER) ((DWORD)this->pe_data->imageNTheaders + sizeof(DWORD));
	this->pe_data->imgOptHeader = (PIMAGE_OPTIONAL_HEADER)((DWORD)this->pe_data->imgFileHeader + sizeof(IMAGE_FILE_HEADER));

	this->pe_data->idataSectionAddress = this->pe_data->imgOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	// Go to section headers array
	this->pe_data->sectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)this->pe_data->imgOptHeader + sizeof(IMAGE_OPTIONAL_HEADER32));
	for(int iter = 1; iter <= this->pe_data->imgFileHeader->NumberOfSections; ++iter){

		if(this->pe_data->sectionHeader->VirtualAddress == this->pe_data->idataSectionAddress.VirtualAddress){
			this->pe_data->idataSectionHeader = this->pe_data->sectionHeader;
		}
		else if(!strcmp((const char*)this->pe_data->sectionHeader->Name, ".rdata")) 
		{
			this->pe_data->rdataSectionHeader = this->pe_data->sectionHeader;
		}

		printf("Name: %s\n", this->pe_data->sectionHeader->Name);
		this->pe_data->sectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)this->pe_data->sectionHeader + sizeof(IMAGE_SECTION_HEADER));
	}

	DWORD rawOffset = (DWORD)(this->pe_data->baseFileBegAddress) + this->pe_data->idataSectionHeader->PointerToRawData;
	this->pe_data->importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(rawOffset);
	for(; this->pe_data->importDescriptor->Name != 0; this->pe_data->importDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)((DWORD)this->pe_data->importDescriptor + sizeof(IMAGE_IMPORT_DESCRIPTOR))){
		printf("\t%s\n", rawOffset + (this->pe_data->importDescriptor->Name - this->pe_data->idataSectionHeader->VirtualAddress));
	}


    rawOffset = (DWORD)this->pe_data->fileDataBegin + (DWORD)this->pe_data->rdataSectionHeader->PointerToRawData;
    _injectData(rawOffset, dllname, sizeof((*dllname)));
    this->pe_data->rdataSectionHeader->SizeOfRawData += sizeof((*dllname));




    /*
    for(int i = 0; i < 300; ++i){
        if(i % 16 == 0){
            printf("\n%p\t", (DWORD)pe_data->bottomPartBegAddress + i);
            printf("%c", *((BYTE*)pe_data->bottomPartBegAddress + i));
        }
        else if(i % 16 != 0){
            printf("%c", *((BYTE*)pe_data->bottomPartBegAddress + i));
        }
	}*/


    LARGE_INTEGER li;
    li.QuadPart = 0;
    SetFilePointerEx(this->pe_data->file, li, NULL, FILE_BEGIN);
    WriteFile(this->pe_data->file, this->pe_data->fileDataBegin, this->pe_data->editedFileSize, &(this->pe_data->bytesWrited), NULL);
	//printf("\tbytes read: %d | bytes write: %d", this->pe_data->bytesReaded, this->pe_data->bytesWrited);
    CloseHandle(this->pe_data->file);
}


LPVOID StaticInjector::_injectData(DWORD rdataPointRVA, LPVOID injection_data, DWORD size){

    printf("data RVA: %p | injection data: %p | size: %d\n\n", (LPVOID)rdataPointRVA, injection_data, size);

	this->pe_data->topPartSize = rdataPointRVA - (DWORD)this->pe_data->baseFileBegAddress;
    this->pe_data->topPartBegAddress = (LPVOID)this->pe_data->baseFileBegAddress;
    this->pe_data->topPartEndAddress = (LPVOID)((DWORD)this->pe_data->baseFileBegAddress + (DWORD)this->pe_data->topPartSize);

    this->pe_data->bottomPartSize = (DWORD)this->pe_data->editedFileSize - (DWORD)this->pe_data->topPartSize;
    this->pe_data->bottomPartBegAddress = (LPVOID)rdataPointRVA;
    this->pe_data->bottomPartEndAddress = (LPVOID)((DWORD)this->pe_data->bottomPartBegAddress + (DWORD)this->pe_data->bottomPartSize);

	this->pe_data->bufferPartSize = this->pe_data->bottomPartSize;
	this->pe_data->bufferPartBegAddress = HeapAlloc(GetProcessHeap(), 0, this->pe_data->bufferPartSize);
    this->pe_data->bufferPartEndAddress = (LPVOID)((DWORD)this->pe_data->bufferPartBegAddress + (DWORD)this->pe_data->bufferPartSize);

    // Write all data from injection pointer to buffer
	CopyMemory(this->pe_data->bufferPartBegAddress, this->pe_data->bottomPartBegAddress, this->pe_data->bufferPartSize);
    ZeroMemory(this->pe_data->bottomPartBegAddress, (DWORD)((DWORD)this->pe_data->extendedFileEndAddress - (DWORD)this->pe_data->bottomPartBegAddress));
    
    // Rewrite data from injection pointer by injection_data
	CopyMemory(this->pe_data->bottomPartBegAddress, injection_data, size);

	this->pe_data->editedFileSize += (size - this->pe_data->bottomPartSize);
    this->pe_data->editedFileBegAddress = this->pe_data->baseFileBegAddress;
    this->pe_data->editedFileEndAddress = (LPVOID)((DWORD)this->pe_data->baseFileBegAddress + (DWORD)this->pe_data->editedFileSize);
	this->pe_data->bottomPartSize = size;

    // Get back saved data to our file
	CopyMemory(this->pe_data->editedFileEndAddress, pe_data->bufferPartBegAddress, pe_data->bufferPartSize);
	this->pe_data->editedFileSize += pe_data->bufferPartSize;
    this->pe_data->editedFileBegAddress = this->pe_data->baseFileBegAddress;
    this->pe_data->editedFileEndAddress = (LPVOID)((DWORD)this->pe_data->baseFileBegAddress + (DWORD)this->pe_data->editedFileSize);

    this->pe_data->bottomPartSize = (DWORD)this->pe_data->editedFileSize - (DWORD)this->pe_data->topPartSize;
    this->pe_data->bottomPartBegAddress = (LPVOID)rdataPointRVA;
    this->pe_data->bottomPartEndAddress = (LPVOID)((DWORD)this->pe_data->bottomPartBegAddress + (DWORD)this->pe_data->bottomPartSize);
}