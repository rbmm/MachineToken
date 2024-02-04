#include "stdafx.h"

_NT_BEGIN
#include "wlog.h"

void DumpToken(WLog& log, HANDLE hToken);

NTSTATUS ImpersonateSystemToken();

NTSTATUS RtlRevertToSelf();

ULONG GetLastErrorEx()
{
	ULONG dwError = GetLastError();
	NTSTATUS status = RtlGetLastNtStatus();
	return RtlNtStatusToDosErrorNoTeb(status) == dwError 
		? HRESULT_FACILITY(status) ? status : HRESULT_FROM_NT(status) 
		: HRESULT_FROM_WIN32(dwError);
}

template <typename T> 
T HR(HRESULT& hr, T t)
{
	hr = t ? S_OK : GetLastErrorEx();
	return t;
}

HRESULT GetMachineToken(_Inout_ WLog& log)
{
	NTSTATUS status = ImpersonateSystemToken();

	if (STATUS_SUCCESS == status)
	{
		if (HMODULE hmod = HR(status, LoadLibraryW(L"certca.dll")))
		{
			union {
				PVOID ppv;
				BOOL (WINAPI * myNetLogonUser)( _In_opt_ PCWSTR UserName, _In_opt_ PCWSTR DomainName, _In_opt_ PCWSTR Password, _Out_ PHANDLE phToken);
			};

			if (ppv = HR(status, GetProcAddress(hmod, (PCSTR)853)))
			{
				HANDLE hToken;
				if (HR(status, myNetLogonUser(0, 0, 0, &hToken)))
				{
					DumpToken(log, hToken);
					NtClose(hToken);
				}
			}

			FreeLibrary(hmod);
		}

		RtlRevertToSelf();
	}
	else
	{
		status |= FACILITY_NT_BIT;
	}

	return status;
}

_NT_END