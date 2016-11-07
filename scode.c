#include "windows.h"
#include <stdio.h>

/* Unsafe and no error checking*/
int main(int argc, char **argv)
{
	if (argc < 2)
	{
		printf("Input the hexstream of your shellcode\n");
		return 1;
	}
	// HWND hWnd = GetConsoleWindow();
        // ShowWindow(hWnd, SW_HIDE );
	int sz = strlen(argv[1]);
	int nsz = sz / 2;
	const char *pos = argv[1];
	unsigned char* val = malloc(sz);
	for (int i = 0; i < sz / 2; i++) 
	{
		sscanf_s(pos, "%2hhx", &val[i]);
		pos += 2;
	}
	void *exec = VirtualAlloc(0, nsz, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(exec, val, nsz);
	((void(*)())exec)();
}
