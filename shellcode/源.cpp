#include<stdio.h>
#include<windows.h>
#include <winternl.h>

typedef FARPROC(WINAPI* GETPROCADDRESS)(
	HMODULE hModule,
	LPCSTR  lpProcName
	);

typedef FARPROC(WINAPI* GETMODULEHANDLEA)(
	LPCSTR lpModuleName
	);

typedef FARPROC(WINAPI* VIRTUALPROTECT)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect
	);

//将shellcode装到另一个节区中，不影响text节区的同时还方便找到对应代码。
#pragma code_seg(".SMC");

void Myshellcode()
{
	//获取PEB结构体的地址
	PPEB PebBaseAddress;
	_asm
	{
		mov eax, dword ptr fs : [0x18]
		mov eax, dword ptr ds : [eax + 0x30]
		mov PebBaseAddress, eax;
	}

	//通过PEB来找到kernel32的基地址
	PPEB_LDR_DATA pPebLdr = PebBaseAddress->Ldr;
	PLDR_DATA_TABLE_ENTRY pLdrDataHeader = (PLDR_DATA_TABLE_ENTRY)pPebLdr->InMemoryOrderModuleList.Flink->Flink->Flink;
	//wprintf(L"%s\n", pLdrDataHeader->FullDllName.Buffer);

	//偏移0x10的地址即为指向kernel.dll基址的指针
	//printf("%x\n", *(pLdrDataHeader->Reserved2));

	//测试是否一样
	//HMODULE libhandle = LoadLibraryA("kernel32.dll");
	//printf("%x ", libhandle);

	PBYTE hkernel = *(PBYTE*)(pLdrDataHeader->Reserved2);
	PIMAGE_DOS_HEADER       pIDH = (PIMAGE_DOS_HEADER)hkernel;
	PIMAGE_OPTIONAL_HEADER  pIOH = (PIMAGE_OPTIONAL_HEADER)(hkernel + pIDH->e_lfanew + 0x18);
	PIMAGE_EXPORT_DIRECTORY PIED = (PIMAGE_EXPORT_DIRECTORY)((DWORD)hkernel + pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	DWORD NumOfFunction = PIED->NumberOfFunctions;
	PIMAGE_IMPORT_BY_NAME FuctionName = NULL;
	GETPROCADDRESS MyGetProcAddress = NULL;


	PIMAGE_THUNK_DATA RVAofNameArrays = (PIMAGE_THUNK_DATA)((DWORD)hkernel + PIED->AddressOfNames);
	PIMAGE_THUNK_DATA RVAofEotArrays = (PIMAGE_THUNK_DATA)((DWORD)hkernel + PIED->AddressOfFunctions);

	//通过比较导出表的函数名称获取GetProcAddress的地址
	DWORD strName[3] = { 0x50746547,0x41636f72,0x65726464 };
	for (int i = 0; i < NumOfFunction; i++)
	{
		FuctionName = (PIMAGE_IMPORT_BY_NAME)((DWORD)hkernel + RVAofNameArrays[i].u1.AddressOfData);

		if (strName[0] == *(DWORD*)((DWORD)FuctionName) && strName[1] == *(DWORD*)((DWORD)FuctionName + 4) && strName[2] == *(DWORD*)((DWORD)FuctionName + 8))
		{
			//这里有个+2的偏移，是通过查看本电脑的kernerl32.dll得到的，确实导出表的函数地址需要偏移2
			MyGetProcAddress = (GETPROCADDRESS)((DWORD)hkernel + RVAofEotArrays[i + 2].u1.AddressOfData);
			break;
		}
	}

	//char GetModuleHandleAFunctionName[] = { 0x47,0x65,0x74,0x4d,0x6f,0x64,0x75,0x6c,0x65,0x48,0x61,0x6e,0x64,0x6c,0x65,0x41,0x00 };
	DWORD GetModuleHandleAFunctionName[6] = { 0 };
	GetModuleHandleAFunctionName[0] = 0x4d746547;
	GetModuleHandleAFunctionName[1] = 0x6c75646f;
	GetModuleHandleAFunctionName[2] = 0x6e614865;
	GetModuleHandleAFunctionName[3] = 0x41656c64;
	GetModuleHandleAFunctionName[4] = 0;

	//获取GetModuleHandleAFunction函数地址
	GETMODULEHANDLEA MyGetModuleHandleA = (GETMODULEHANDLEA)MyGetProcAddress((HMODULE)hkernel, (char*)GetModuleHandleAFunctionName);

	PBYTE BaseAddress = (PBYTE)MyGetModuleHandleA(NULL);


	PIMAGE_DOS_HEADER       pExeIDH = (PIMAGE_DOS_HEADER)BaseAddress;
	PIMAGE_OPTIONAL_HEADER  pExeIOH = (PIMAGE_OPTIONAL_HEADER)(BaseAddress + pExeIDH->e_lfanew + 0x18);
	PIMAGE_FILE_HEADER      pExeIFH = (PIMAGE_FILE_HEADER)(BaseAddress + pExeIDH->e_lfanew + 4);
	PIMAGE_SECTION_HEADER   pExeISH = (PIMAGE_SECTION_HEADER)(BaseAddress + pExeIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	DWORD OldSectionNumber = pExeIFH->NumberOfSections - 1;
	DWORD dwTextsize;
	DWORD* pTextStart = NULL;
	DWORD TextMax = pExeISH->Misc.VirtualSize + pExeISH->VirtualAddress;

	//寻找.text节区，获取其起始RVA和大小，解密会用到
	for (int i = 0; i < OldSectionNumber; pExeISH++)
	{
		if ((DWORD) * (DWORD*)pExeISH->Name == 0x7865742e)
		{
			dwTextsize = pExeISH->Misc.VirtualSize;
			pTextStart = (DWORD*)(pExeISH->VirtualAddress + (DWORD)pExeIDH);
			break;
		}
	}

	//获取VirtualProtectFunction地址，修改.text节区为可写可读可执行
	char VirtualProtectFunctionName[15] = { 0x56,0x69,0x72,0x74,0x75,0x61,0x6c,0x50,0x72,0x6f,0x74,0x65,0x63,0x74, 0x00 };
	VIRTUALPROTECT MyVirtualProtect = (VIRTUALPROTECT)MyGetProcAddress((HMODULE)hkernel, VirtualProtectFunctionName);

	DWORD flOldProtect;
	MyVirtualProtect((LPVOID)pTextStart, dwTextsize, PAGE_EXECUTE_READWRITE, &flOldProtect);


	PIMAGE_BASE_RELOCATION  pExeIBR = (PIMAGE_BASE_RELOCATION)((DWORD)BaseAddress + pExeIOH->DataDirectory[5].VirtualAddress);
	DWORD dwImageBase = *(DWORD*)(pExeIOH->ImageBase + pExeIOH->AddressOfEntryPoint + 4);

	DWORD Round = NULL;
	Round = dwTextsize / 4;

	if (pExeIOH->DataDirectory[5].VirtualAddress == 0)
	{
		//没有重定位表

		for (int i = 0; i < Round; i++)
		{
			*(unsigned int*)(pTextStart + i) = *(unsigned int*)(pTextStart + i) ^ 0x12345678;
		}
	}
	else
	{
		//将text节区还原为重定位表之前的情况。
		while (pExeIBR->VirtualAddress != 0)
		{

			DWORD RvaofBlock = pExeIBR->VirtualAddress;
			//定义成一个WORD的指针，方便取值计算
			WORD* RvaArrays = (WORD*)((DWORD)pExeIBR + sizeof(IMAGE_BASE_RELOCATION));
			//算出这个重定位表块需要修改多少个RAV
			int NumofRva = (pExeIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

			//修改每个块中的重定位表信息
			for (int i = 0; i < NumofRva; i++)
			{
				if ((RvaArrays[i] & 0xfff) + RvaofBlock > TextMax)
				{
					continue;
				}
				//32位程序一般Type就是3，也就是IMAGE_REL_BASED_HIGHLOW
				DWORD* pAddr = (DWORD*)((DWORD)BaseAddress + (RvaArrays[i] & 0xfff) + RvaofBlock);
				*pAddr = *pAddr + dwImageBase - (DWORD)BaseAddress;
			}

			pExeIBR = (PIMAGE_BASE_RELOCATION)((DWORD)pExeIBR + pExeIBR->SizeOfBlock);
		}

		//解密
		for (int i = 0; i < Round; i++)
		{
			*(DWORD*)(pTextStart + i) = *(DWORD*)(pTextStart + i) ^ 0x12345678;
		}

		//再次进行重定位表。
		pExeIBR = (PIMAGE_BASE_RELOCATION)((DWORD)BaseAddress + pExeIOH->DataDirectory[5].VirtualAddress);

		while (pExeIBR->VirtualAddress != 0)
		{

			DWORD RvaofBlock = pExeIBR->VirtualAddress;
			//定义成一个WORD的指针，方便取值计算
			WORD* RvaArrays = (WORD*)((DWORD)pExeIBR + sizeof(IMAGE_BASE_RELOCATION));
			//算出这个重定位表块需要修改多少个RAV
			int NumofRva = (pExeIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

			//修改每个块中的重定位表信息
			for (int i = 0; i < NumofRva; i++)
			{
				if ((RvaArrays[i] & 0xfff) + RvaofBlock > TextMax)
				{
					continue;
				}
				//32位程序一般Type就是3，也就是IMAGE_REL_BASED_HIGHLOW
				DWORD* pAddr = (DWORD*)((DWORD)BaseAddress + (RvaArrays[i] & 0xfff) + RvaofBlock);
				*pAddr = *pAddr - dwImageBase + (DWORD)BaseAddress;
			}

			pExeIBR = (PIMAGE_BASE_RELOCATION)((DWORD)pExeIBR + pExeIBR->SizeOfBlock);
		}
	}

}
void func2() {
}

#pragma code_seg()
#pragma comment(linker, "/SECTION:.SMC,ERW")
int main()
{
	//用来导出shellcode的，但是由于只有Debug模式下的才好修改，所以还是在ida里面提取shellcode吧。
	PBYTE Start, End;
	Start = (PBYTE)Myshellcode;
	End = (PBYTE)func2;
	int lenth = 0;

	for (; Start < End; Start++)
	{
		printf("\\x%02x", *Start);
		lenth++;
	}
	printf("\n%x", lenth);
	Myshellcode();
}