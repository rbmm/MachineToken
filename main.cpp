#include "stdafx.h"

_NT_BEGIN
#include "wlog.h"

HRESULT GetMachineToken(_Inout_ WLog& log);

void DumpToken(HWND hwnd, HANDLE hToken);

int CustomMessageBox(HWND hWnd, PCWSTR lpText, PCWSTR lpszCaption, UINT uType)
{
	PCWSTR pszName = 0;

	switch (uType & MB_ICONMASK)
	{
	case MB_ICONINFORMATION:
		pszName = IDI_INFORMATION;
		break;
	case MB_ICONQUESTION:
		pszName = IDI_QUESTION;
		break;
	case MB_ICONWARNING:
		pszName = IDI_WARNING;
		break;
	case MB_ICONERROR:
		pszName = IDI_ERROR;
		break;
	}

	MSGBOXPARAMS mbp = {
		sizeof(mbp),
		hWnd,
		(HINSTANCE)&__ImageBase,
		lpText, 
		lpszCaption, 
		(uType & ~MB_ICONMASK)|MB_USERICON,
		MAKEINTRESOURCE(1)
	};

	return MessageBoxIndirect(&mbp);
}

int ShowErrorBox(HWND hWnd, PCWSTR lpCaption, HRESULT dwError, UINT uType)
{
	int r = 0;
	LPCVOID lpSource = 0;
	ULONG dwFlags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;

	if ((dwError & FACILITY_NT_BIT) || (0 > dwError && HRESULT_FACILITY(dwError) == FACILITY_NULL))
	{
		dwError &= ~FACILITY_NT_BIT;
__nt:
		dwFlags = FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;

		static HMODULE ghnt;
		if (!ghnt && !(ghnt = GetModuleHandle(L"ntdll"))) return 0;
		lpSource = ghnt;
	}

	PWSTR lpText;
	if (FormatMessageW(dwFlags, lpSource, dwError, 0, (PWSTR)&lpText, 0, 0))
	{
		r = CustomMessageBox(hWnd, lpText, lpCaption, uType);
		LocalFree(lpText);
	}
	else if (dwFlags & FORMAT_MESSAGE_FROM_SYSTEM)
	{
		goto __nt;
	}

	return r;
}

HRESULT DumpToken(HWND hwnd)
{
	WLog log;
	HRESULT hr = log.Init(0x10000);
	if (NOERROR == hr)
	{
		hr = GetMachineToken(log);

		log >> hwnd;
	}

	return hr;
}

HFONT CreateFont()
{
	NONCLIENTMETRICS ncm = { sizeof(ncm) };
	if (SystemParametersInfo(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0))
	{
		ncm.lfMenuFont.lfQuality = CLEARTYPE_QUALITY;
		ncm.lfMenuFont.lfPitchAndFamily = FIXED_PITCH|FF_MODERN;
		ncm.lfMenuFont.lfWeight = FW_NORMAL;
		ncm.lfMenuFont.lfHeight = -ncm.iMenuHeight;
		wcscpy(ncm.lfMenuFont.lfFaceName, L"Courier New");

		return CreateFontIndirectW(&ncm.lfMenuFont);
	}

	return 0;
}

void NTAPI ep(void*)
{
	BOOLEAN b;
	RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &b);

	if (HWND hwnd = CreateWindowExW(0, WC_EDIT, L"GetMachineToken", WS_OVERLAPPEDWINDOW|WS_VSCROLL|ES_MULTILINE,
		CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, 0, 0, 0, 0))
	{
		ULONG n = 8;
		SendMessage(hwnd, EM_SETTABSTOPS, 1, (LPARAM)&n);

		HFONT hfont = 0;
		HICON hiS = 0, hiB = 0;

		if (S_OK == LoadIconWithScaleDown((HINSTANCE)&__ImageBase, MAKEINTRESOURCE(1), 
			GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), &hiS))
		{
			SendMessage(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hiS);
		}

		if (S_OK == LoadIconWithScaleDown((HINSTANCE)&__ImageBase, MAKEINTRESOURCE(1), 
			GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON), &hiB))
		{
			SendMessage(hwnd, WM_SETICON, ICON_BIG, (LPARAM)hiB);
		}

		if (hfont = CreateFont())
		{
			SendMessage(hwnd, WM_SETFONT, (WPARAM)hfont, 0);
		}

		if (HRESULT hr = DumpToken(hwnd))
		{
			DestroyWindow(hwnd);

			ShowErrorBox(0, 0, hr, MB_ICONHAND);
		}
		else
		{
			ShowWindow(hwnd, SW_SHOWNORMAL);

			MSG msg;
			while (IsWindow(hwnd) && 0 < GetMessageW(&msg, 0, 0, 0))
			{
				TranslateMessage(&msg);
				DispatchMessageW(&msg);
			}
		}

		if (hfont)
		{
			DeleteObject(hfont);
		}

		if (hiB) DestroyIcon(hiB);
		if (hiS) DestroyIcon(hiS);
	}

	ExitProcess(0);
}

_NT_END