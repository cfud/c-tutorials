// RunPE.cpp : Defines the entry point for the console application.
//
/*

#include <Windows.h>
#include <TlHelp32.h>

#include <iostream>
#include <fstream>

HANDLE MapFileToMemory(LPCSTR filename)
{
	std::streampos size;
	std::fstream file(filename, std::ios::in | std::ios::binary | std::ios::ate);
	if (file.is_open())
	{
		size = file.tellg();

		char* Memblock = new char[size]();

		file.seekg(0, std::ios::beg);
		file.read(Memblock, size);
		file.close();

		return Memblock;
	}
	return 0;
}

int RunPortableExecutable(void* Image)
{
	PIMAGE_DOS_HEADER DosHeader;
	PIMAGE_NT_HEADERS NtHeader;
	PIMAGE_SECTION_HEADER SectionHeader;

	PROCESS_INFORMATION PI;
	STARTUPINFOA SI;

	PCONTEXT CTX;
	PDWORD dwImageBase;
	
	LPVOID pImageBase;
	int Count;

	char FilePath[1024];

	GetModuleFileNameA(0, LPSTR(FilePath), 1024);

	DosHeader = PIMAGE_DOS_HEADER(Image);

	NtHeader = PIMAGE_NT_HEADERS(DWORD(Image) + DosHeader->e_lfanew);

	if (NtHeader->Signature == IMAGE_NT_SIGNATURE)
	{
		RtlZeroMemory(&SI, sizeof(SI));
		RtlZeroMemory(&PI, sizeof(PI));

		if (CreateProcessA(FilePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &SI, &PI))
		{
			CTX = PCONTEXT(VirtualAlloc(NULL, sizeof(CTX), MEM_COMMIT, PAGE_READWRITE));
			CTX->ContextFlags = CONTEXT_FULL;

			if (GetThreadContext(PI.hThread, LPCONTEXT(CTX)))
			{
				ReadProcessMemory(PI.hProcess, LPCVOID(CTX->Ebx + 8), LPVOID(&dwImageBase), 4, NULL);

				pImageBase = VirtualAllocEx(PI.hProcess, LPVOID(NtHeader->OptionalHeader.ImageBase),
					NtHeader->OptionalHeader.SizeOfImage, 0x3000, PAGE_EXECUTE_READWRITE);

				WriteProcessMemory(PI.hProcess, pImageBase, Image, NtHeader->OptionalHeader.SizeOfHeaders, NULL);

				for (Count = 0; Count < NtHeader->FileHeader.NumberOfSections; Count++)
				{
					SectionHeader = PIMAGE_SECTION_HEADER(DWORD(Image) + DosHeader->e_lfanew + 248 + (Count * 40));

					WriteProcessMemory(PI.hProcess, LPVOID(DWORD(pImageBase) + SectionHeader->VirtualAddress),
						LPVOID(DWORD(Image) + SectionHeader->PointerToRawData), SectionHeader->SizeOfRawData, NULL);
				}
				WriteProcessMemory(PI.hProcess, LPVOID(CTX->Ebx + 8),
					LPVOID(&NtHeader->OptionalHeader.ImageBase), 4, NULL);

				CTX->Eax = DWORD(pImageBase) + NtHeader->OptionalHeader.AddressOfEntryPoint;
				SetThreadContext(PI.hThread, LPCONTEXT(CTX));
				ResumeThread(PI.hThread);

				return 1;
			}
		}
	}
	VirtualFree(Image, 0, MEM_RELEASE);
}

int main(int argc, char* argv[])
{
	void* raw = MapFileToMemory("D:\\Lobby.exe");
    RunPortableExecutable(raw); // run the executable
	return 0;
}

*/