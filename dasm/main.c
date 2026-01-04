#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include "getopt.h"
#include "x86_dasm.h"
#include "MemoryModule.h"


int is_readable(void* addr)
{
	MEMORY_BASIC_INFORMATION mbi;
	if (VirtualQuery(addr, &mbi, sizeof(mbi)))
		return mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE);
	return 0;
}

BOOL read_file(LPCSTR filename, BYTE** buffer, DWORD* fileSize)
{
	HANDLE hFile = CreateFileA(filename, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;

	*fileSize = GetFileSize(hFile, NULL);
;
	*buffer = (BYTE*)malloc(*fileSize);
	if (*buffer == NULL) 
	{
		CloseHandle(hFile);
		return FALSE;
	}

	DWORD bytesRead;
	if (!ReadFile(hFile, *buffer, *fileSize, &bytesRead, NULL) || bytesRead != *fileSize) 
	{
		free(*buffer);
		CloseHandle(hFile);
		return FALSE;
	}

	CloseHandle(hFile);
	return TRUE;
}

PVOID reload_module(const char* dllname)
{
	char dllPath[MAX_PATH] = { 0 };
	PBYTE buffer = NULL;
	DWORD fileSize = 0;
	LPVOID baseAddress = NULL;

	if (strstr(dllname, ":"))
		wsprintfA(dllPath, "%s", dllname);
	else
		wsprintfA(dllPath, "C:\\Windows\\System32\\%s", dllname);

	if (read_file(dllPath, &buffer, &fileSize))
	{
		baseAddress = MemoryLoadLibrary(buffer, fileSize);
		free(buffer);
	}

	return baseAddress;
}

int main(int argc, char* argv[])
{
	ulong_t j = 0;
	uint64_t rip = 0;
	x86_dasm_context_t x86_dctx = { 0 };

	char* dll = NULL;
	char* func = NULL;
	int length = 32;
	BOOL ripMode = FALSE;
	BOOL reload = FALSE;
	HMODULE module = NULL;

	char ch;
	while ((ch = getopt(argc, argv, "d:f:i:l:r")) != EOF)
	{
		switch (ch)
		{
		case 'd':
			dll = optarg;
			break;
		case 'f':
			func = optarg;
			break;
		case 'i':
			ripMode = TRUE;
			rip = strtoull(optarg, NULL, 16);
			break;
		case 'l':
			length = atoi(optarg);
			break;
		case 'r':
			reload = TRUE;
			break;
		default:
			break;
		}
	}

	if ((dll == NULL || func == NULL) && rip == 0)
	{
		if (ripMode && !is_readable(rip))
		{
			printf("invalid address.\n");
			return;
		}
		return 1;
	}

	char* base = NULL;
	if (dll != NULL && func != NULL)
	{
		if (reload)
		{
			module = reload_module(dll);
			if (module != NULL)
				base = (uint64_t)MemoryGetProcAddress(module, func);
		}
		else
		{
			module = GetModuleHandleA(dll);
			if (module == NULL)
				module = LoadLibraryA(dll);
			if (module != NULL)
				base = (uint64_t)GetProcAddress(module, func);
		}

		if(module == NULL)
			printf("load error.\n");
		else if(base == NULL)
			printf("get proc error.\n");
	}
	else
		base = (char*)rip;

	if (base == NULL)
		return;

	if (!is_readable(base))
	{
		printf("invalid address.\n");
		return;
	}

	rip = base;

#ifdef _M_X64
	x86_dctx.dmode = X86_DMODE_64BIT;
#else
	x86_dctx.dmode = X86_DMODE_32BIT;
#endif

	/* disassemble the code */
	while (j < length)
	{
		x86_set_buffer(&x86_dctx, &base[j]);
		x86_set_ip(&x86_dctx, rip + j);

		if (x86_dasm(&x86_dctx) < 0)
			break;

		printf("%04" PRIX64 " | ", rip + j);

		/* print the bytes */
		for (int i = 0; i < 8 - x86_dctx.len; i++)
			printf("   ");

		for (int i = 0; i < x86_dctx.len; i++)
			printf("%02X ", x86_dctx.buffer[i]);

		/* print the decoded instruction */
		printf(" | %s\n", x86_dctx.inst_str);

		j += x86_dctx.len;
	}

	if (reload && module != NULL)
		MemoryFreeLibrary(module);

	return 0;
}