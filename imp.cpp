#include "stdafx.h"

_NT_BEGIN

extern const OBJECT_ATTRIBUTES zoa = { sizeof(zoa) };

NTSTATUS RtlRevertToSelf()
{
	HANDLE hToken = 0;
	return NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &hToken, sizeof(hToken));
}

NTSTATUS GetProcessList(_Out_ SYSTEM_PROCESS_INFORMATION** ppspi)
{
	ULONG cb = 0x100000-0x1000;
	NTSTATUS status;

	do 
	{
		status = STATUS_NO_MEMORY;

		if (PVOID buf = LocalAlloc(LMEM_FIXED, cb += 0x1000))
		{
			if (0 <= (status = NtQuerySystemInformation(SystemExtendedProcessInformation, buf, cb, &cb)))
			{
				*ppspi = (SYSTEM_PROCESS_INFORMATION*)buf;
				return S_OK;
			}
			LocalFree(buf);
		}

	} while (STATUS_INFO_LENGTH_MISMATCH == status);

	return status;
}

NTSTATUS GetSystemToken(PSYSTEM_PROCESS_INFORMATION pspi, PHANDLE phSysToken)
{
	NTSTATUS status;

	ULONG NextEntryOffset = 0;

	do 
	{
		(ULONG_PTR&)pspi += NextEntryOffset;

		HANDLE hProcess, hToken, hNewToken;

		if (pspi->InheritedFromUniqueProcessId && pspi->UniqueProcessId)
		{
			static SECURITY_QUALITY_OF_SERVICE sqos = {
				sizeof sqos, SecurityImpersonation, SECURITY_DYNAMIC_TRACKING, FALSE
			};

			static OBJECT_ATTRIBUTES soa = { sizeof(soa), 0, 0, 0, 0, &sqos };

			if (0 <= NtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION, const_cast<OBJECT_ATTRIBUTES*>(&zoa), &pspi->TH->ClientId))
			{
				status = NtOpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken);

				NtClose(hProcess);

				if (0 <= status)
				{
					status = NtDuplicateToken(hToken, TOKEN_ADJUST_PRIVILEGES|TOKEN_IMPERSONATE, 
						&soa, FALSE, TokenImpersonation, &hNewToken);

					NtClose(hToken);

					if (0 <= status)
					{
						BEGIN_PRIVILEGES(tp, 2)
							LAA(SE_TCB_PRIVILEGE),
							LAA(SE_DEBUG_PRIVILEGE),
						END_PRIVILEGES	

						if (STATUS_SUCCESS == NtAdjustPrivilegesToken(hNewToken, FALSE, (PTOKEN_PRIVILEGES)&tp, 0, 0, 0))	
						{
							*phSysToken = hNewToken;
							return STATUS_SUCCESS;
						}

						NtClose(hNewToken);
					}
				}
			}
		}

	} while (NextEntryOffset = pspi->NextEntryOffset);

	return STATUS_UNSUCCESSFUL;
}

NTSTATUS ImpersonateSystemToken(PSYSTEM_PROCESS_INFORMATION pspi)
{
	HANDLE hToken;

	NTSTATUS status = GetSystemToken(pspi, &hToken);

	if (0 <= status)
	{
		status = NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &hToken, sizeof(hToken));
		NtClose(hToken);
	}
	return status;
}

NTSTATUS ImpersonateSystemToken()
{
	PSYSTEM_PROCESS_INFORMATION pspi;
	NTSTATUS status = GetProcessList(&pspi);
	if (0 <= status)
	{
		status = ImpersonateSystemToken(pspi);
		LocalFree(pspi);
	}

	return status;
}

_NT_END