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

//��shellcodeװ����һ�������У���Ӱ��text������ͬʱ�������ҵ���Ӧ���롣
#pragma code_seg(".SMC");

void Myshellcode()
{
	//��ȡPEB�ṹ��ĵ�ַ
	PPEB PebBaseAddress;
	_asm
	{
		mov eax, dword ptr fs : [0x18]
		mov eax, dword ptr ds : [eax + 0x30]
		mov PebBaseAddress, eax;
	}

	//ͨ��PEB���ҵ�kernel32�Ļ���ַ
	PPEB_LDR_DATA pPebLdr = PebBaseAddress->Ldr;
	PLDR_DATA_TABLE_ENTRY pLdrDataHeader = (PLDR_DATA_TABLE_ENTRY)pPebLdr->InMemoryOrderModuleList.Flink->Flink->Flink;
	//wprintf(L"%s\n", pLdrDataHeader->FullDllName.Buffer);

	//ƫ��0x10�ĵ�ַ��Ϊָ��kernel.dll��ַ��ָ��
	//printf("%x\n", *(pLdrDataHeader->Reserved2));

	//�����Ƿ�һ��
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

	//ͨ���Ƚϵ�����ĺ������ƻ�ȡGetProcAddress�ĵ�ַ
	DWORD strName[3] = { 0x50746547,0x41636f72,0x65726464 };
	for (int i = 0; i < NumOfFunction; i++)
	{
		FuctionName = (PIMAGE_IMPORT_BY_NAME)((DWORD)hkernel + RVAofNameArrays[i].u1.AddressOfData);

		if (strName[0] == *(DWORD*)((DWORD)FuctionName) && strName[1] == *(DWORD*)((DWORD)FuctionName + 4) && strName[2] == *(DWORD*)((DWORD)FuctionName + 8))
		{
			//�����и�+2��ƫ�ƣ���ͨ���鿴�����Ե�kernerl32.dll�õ��ģ�ȷʵ������ĺ�����ַ��Ҫƫ��2
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

	//��ȡGetModuleHandleAFunction������ַ
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

	//Ѱ��.text��������ȡ����ʼRVA�ʹ�С�����ܻ��õ�
	for (int i = 0; i < OldSectionNumber; pExeISH++)
	{
		if ((DWORD) * (DWORD*)pExeISH->Name == 0x7865742e)
		{
			dwTextsize = pExeISH->Misc.VirtualSize;
			pTextStart = (DWORD*)(pExeISH->VirtualAddress + (DWORD)pExeIDH);
			break;
		}
	}

	//��ȡVirtualProtectFunction��ַ���޸�.text����Ϊ��д�ɶ���ִ��
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
		//û���ض�λ��

		for (int i = 0; i < Round; i++)
		{
			*(unsigned int*)(pTextStart + i) = *(unsigned int*)(pTextStart + i) ^ 0x12345678;
		}
	}
	else
	{
		//��text������ԭΪ�ض�λ��֮ǰ�������
		while (pExeIBR->VirtualAddress != 0)
		{

			DWORD RvaofBlock = pExeIBR->VirtualAddress;
			//�����һ��WORD��ָ�룬����ȡֵ����
			WORD* RvaArrays = (WORD*)((DWORD)pExeIBR + sizeof(IMAGE_BASE_RELOCATION));
			//�������ض�λ�����Ҫ�޸Ķ��ٸ�RAV
			int NumofRva = (pExeIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

			//�޸�ÿ�����е��ض�λ����Ϣ
			for (int i = 0; i < NumofRva; i++)
			{
				if ((RvaArrays[i] & 0xfff) + RvaofBlock > TextMax)
				{
					continue;
				}
				//32λ����һ��Type����3��Ҳ����IMAGE_REL_BASED_HIGHLOW
				DWORD* pAddr = (DWORD*)((DWORD)BaseAddress + (RvaArrays[i] & 0xfff) + RvaofBlock);
				*pAddr = *pAddr + dwImageBase - (DWORD)BaseAddress;
			}

			pExeIBR = (PIMAGE_BASE_RELOCATION)((DWORD)pExeIBR + pExeIBR->SizeOfBlock);
		}

		//����
		for (int i = 0; i < Round; i++)
		{
			*(DWORD*)(pTextStart + i) = *(DWORD*)(pTextStart + i) ^ 0x12345678;
		}

		//�ٴν����ض�λ��
		pExeIBR = (PIMAGE_BASE_RELOCATION)((DWORD)BaseAddress + pExeIOH->DataDirectory[5].VirtualAddress);

		while (pExeIBR->VirtualAddress != 0)
		{

			DWORD RvaofBlock = pExeIBR->VirtualAddress;
			//�����һ��WORD��ָ�룬����ȡֵ����
			WORD* RvaArrays = (WORD*)((DWORD)pExeIBR + sizeof(IMAGE_BASE_RELOCATION));
			//�������ض�λ�����Ҫ�޸Ķ��ٸ�RAV
			int NumofRva = (pExeIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

			//�޸�ÿ�����е��ض�λ����Ϣ
			for (int i = 0; i < NumofRva; i++)
			{
				if ((RvaArrays[i] & 0xfff) + RvaofBlock > TextMax)
				{
					continue;
				}
				//32λ����һ��Type����3��Ҳ����IMAGE_REL_BASED_HIGHLOW
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
	//��������shellcode�ģ���������ֻ��Debugģʽ�µĲź��޸ģ����Ի�����ida������ȡshellcode�ɡ�
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