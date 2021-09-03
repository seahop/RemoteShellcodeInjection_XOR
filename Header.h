#pragma once
void Helper();
void xor_decrypt(unsigned char*, int, char*, int);
int GetUserFromRemoteProcess(DWORD, TCHAR*, TCHAR*);
int GetLogonFromToken(HANDLE, TCHAR*, TCHAR*);
DWORD ProcessID(const char*, TCHAR*, TCHAR*);
BOOL GetCurrentUserAndDomain(PTSTR, PDWORD, PTSTR, PDWORD);
void GoForth(const char*);