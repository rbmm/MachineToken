#include "stdafx.h"

_NT_BEGIN
#include <security.h>

#include "wlog.h"

void DumpToken(WLog& log, HANDLE hToken);

NTSTATUS ImpersonateSystemToken();

NTSTATUS RtlRevertToSelf();

struct SharedCred
{
	CredHandle m_hCred {};

	~SharedCred()
	{
		if (m_hCred.dwLower | m_hCred.dwUpper) FreeCredentialsHandle(&m_hCred);
	}

	SECURITY_STATUS Acquire(PCWSTR pszPrincipal, PCWSTR pszPackage, ULONG fCredentialUse, PSEC_WINNT_AUTH_IDENTITY_W pAuthData = 0)
	{ 
		return AcquireCredentialsHandleW(const_cast<PWSTR>(pszPrincipal), 
			const_cast<PWSTR>(pszPackage), fCredentialUse, 0, pAuthData, 0, 0, &m_hCred, 0);
	}
};

class __declspec(novtable) CKerbStream : public CtxtHandle
{
protected:
	SharedCred* m_pCred = 0;
	PWSTR m_pszTargetName = 0;
	CKerbStream* _M_pLink = 0;

private:

	SECURITY_STATUS ProcessSecurityContext(PSecBufferDesc pInput, PSecBufferDesc pOutput);

	SECURITY_STATUS ProcessSecurityContext(PSTR& rbuf, DWORD& rcb);

	virtual void OnEncryptDecryptError(SECURITY_STATUS );

	//////////////////////////////////////////////////////////////////////////
	//++ impl

	virtual SECURITY_STATUS OnEndHandshake() = 0;

	virtual ULONG ContextRequirements()
	{
		return ASC_REQ_ALLOCATE_MEMORY;
	}

	virtual SECURITY_STATUS Send(_In_ PSecBufferDesc pInput)
	{
		return _M_pLink->Process(pInput);
	}

public:
	virtual BOOL IsServer(_Out_opt_ PBOOLEAN pbMutual = 0) = 0;

	void SetCred(SharedCred* pCred)
	{
		m_pCred = pCred;
	}

	void SetLink(CKerbStream* pLink)
	{
		_M_pLink = pLink;
	}

	SECURITY_STATUS QueryContext(ULONG ulAttribute, PVOID pBuffer)
	{
		return QueryContextAttributesW(this, ulAttribute, pBuffer);
	}

	SECURITY_STATUS Process(_In_ PSecBufferDesc pInput);

protected:

	CKerbStream()
	{
		dwLower = 0;
		dwUpper = 0;
	}

	~CKerbStream()
	{
		if (dwLower | dwUpper) 
		{
			::DeleteSecurityContext(this);
			dwLower = 0;
			dwUpper = 0;
		}
	}
};

void CKerbStream::OnEncryptDecryptError([[maybe_unused]] HRESULT hr)
{
	DbgPrint("\n\n%p>%s(%x) !!!!!!!!!!\n\n", this, __FUNCTION__, hr);
}

SECURITY_STATUS CKerbStream::Process(_In_ PSecBufferDesc pInput)
{
	SecBuffer OutBuf = { 0, SECBUFFER_TOKEN }; 

	SecBufferDesc sbd_out = { SECBUFFER_VERSION, 1, &OutBuf };

	SECURITY_STATUS ss = ProcessSecurityContext(pInput, &sbd_out), hr;

	if (0 <= (hr = ss))
	{
		if (OutBuf.cbBuffer)
		{
			hr = Send(&sbd_out);

			FreeContextBuffer(OutBuf.pvBuffer);
		}

		if (SEC_E_OK == ss && SEC_E_OK == hr)
		{
			hr = OnEndHandshake();
		}
	}

	return hr;
}

SECURITY_STATUS CKerbStream::ProcessSecurityContext(PSecBufferDesc pInput, PSecBufferDesc pOutput)
{
	//DbgPrint("%p>%c:ProcessSecurityContext<%p.%p> %S\n", this, IsServer() ? 'S' : 'C', dwLower, dwUpper, m_pszTargetName);

	PCtxtHandle phContext = 0, phNewContext = 0;

	dwLower | dwUpper ? phContext = this : phNewContext = this;

	ULONG fContextReq = ContextRequirements();
	BOOLEAN bMutual;
	return IsServer(&bMutual) ? 
		::AcceptSecurityContext(&m_pCred->m_hCred, phContext, pInput, 
		fContextReq, SECURITY_NATIVE_DREP, phNewContext, pOutput, &fContextReq, 0) : 
	::InitializeSecurityContextW(&m_pCred->m_hCred, 
		phContext, m_pszTargetName, fContextReq, 
		0, SECURITY_NATIVE_DREP, pInput, 0, phNewContext, pOutput, &fContextReq, 0);
}

class CSrv : public CKerbStream
{
	WLog& _M_log;

	virtual BOOL IsServer(_Out_opt_ PBOOLEAN pbMutual = 0)
	{
		if (pbMutual) *pbMutual = TRUE;
		return TRUE;
	}

	virtual SECURITY_STATUS OnEndHandshake()
	{
		SecPkgContext_AccessToken at;

		if (HRESULT hr = QueryContext(SECPKG_ATTR_ACCESS_TOKEN, &at))
		{
			return hr;
		}
		
		DumpToken(_M_log, at.AccessToken);

		return SEC_E_OK;
	}
public:
	CSrv(WLog& log) : _M_log(log)
	{
	}
};

class CCli : public CKerbStream
{
	virtual BOOL IsServer(_Out_opt_ PBOOLEAN pbMutual = 0)
	{
		if (pbMutual) *pbMutual = FALSE;
		return FALSE;
	}

	virtual SECURITY_STATUS OnEndHandshake()
	{
		return SEC_E_OK;
	}

public:

	void SetUPN(PWSTR pszTargetName)
	{
		m_pszTargetName = pszTargetName;
	}
};

HRESULT GetMachineToken(WLog& log)
{
	NTSTATUS hr = ImpersonateSystemToken();

	if (STATUS_SUCCESS == hr)
	{
		CCli c;
		CSrv s(log);
		SharedCred scC, scS;

		union {
			PVOID buf = 0;
			PWSTR ComputerName;
		};

		if (0 <= (hr = scS.Acquire(0, MICROSOFT_KERBEROS_NAME_W, SECPKG_CRED_INBOUND)))
		{
			SEC_WINNT_AUTH_IDENTITY_W AuthData {};

			ULONG cchMax = 0, cch = 0x40;

			PVOID stack = alloca(sizeof(WCHAR));
			do 
			{
				if (cchMax < cch)
				{
					cchMax = RtlPointerToOffset(buf = alloca((cch - cchMax) * sizeof(WCHAR)), stack) / sizeof(WCHAR);
				}

				hr = BOOL_TO_ERROR(GetComputerNameExW(ComputerNamePhysicalNetBIOS, ComputerName, &(cch = cchMax)));

			} while (ERROR_MORE_DATA == hr);

			if (NOERROR == hr)
			{
				wcscpy(ComputerName + cch, L"$");
				AuthData.User = (USHORT*)ComputerName;
				AuthData.UserLength = cch + 1;
				AuthData.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

				hr = scC.Acquire(0, MICROSOFT_KERBEROS_NAME_W, SECPKG_CRED_OUTBOUND, &AuthData);
			}
		}

		RtlRevertToSelf();

		if (0 <= hr)
		{
			c.SetCred(&scC);
			s.SetCred(&scS);

			s.SetLink(&c);
			c.SetLink(&s);

			c.SetUPN(ComputerName);
			hr = c.Process(0);
		}
	}
	else
	{
		hr |= FACILITY_NT_BIT;
	}

	return hr;
}

_NT_END