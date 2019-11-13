#include <iostream>
#include <Windows.h>
#include <UserEnv.h>
#include <dsgetdc.h>
#include <Lm.h>

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "userenv.lib")

PCWSTR Win32ErrorToString(DWORD dwErr)
{
    const int maxSite = 512;
    PCWSTR szDefaultMessage = L"<< unknown message for this error code >>";
    WCHAR wszMsgBuff[maxSite];
    DWORD dwChars;

    dwChars = FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        dwErr,
        NULL,
        wszMsgBuff,
        maxSite,
        nullptr
    );

    if (!dwChars)
    {
        HINSTANCE hInst;

        hInst = LoadLibraryW(L"Ntdsbmsg.dll");
        if (!hInst)
        {
            return szDefaultMessage;
        }

        dwChars = FormatMessageW(
            FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS,
            hInst,
            dwErr,
            NULL,
            wszMsgBuff,
            maxSite,
            nullptr
        );

        FreeLibrary(hInst);
    }

    return (dwChars ? wszMsgBuff : szDefaultMessage);
}

int wmain(int argc, PWCHAR argv[])
{
    if (argc < 4)
    {
        std::wcout << L"ERROR: Invalid number of arguments passed." << std::endl;
        std::wcout << L"\tArg1: User Account (ex. Domain\\UserName)" << std::endl;
        std::wcout << L"\tArg2: User Account Password" << std::endl;
        std::wcout << L"\tArg3: Process to start" << std::endl;

        return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);
    }

    DWORD status = S_OK;
    std::wstring userAccount = argv[1];
    std::wstring userPassword = argv[2];
    std::wstring cmdLine = argv[3];

    std::wstring userName = userAccount.substr(userAccount.find_first_of(L"\\") + 1, userAccount.length());
    std::wstring domainName = userAccount.substr(0, userAccount.find_first_of(L"\\"));

    PDOMAIN_CONTROLLER_INFOW pDomainControllerInfo = nullptr;
    LPUSER_INFO_4 pUserInfo = nullptr;
    PROFILEINFOW pProfileInfo;
    HANDLE hToken = NULL;
    LPVOID pEnvironmentBlock = nullptr;
    STARTUPINFOW startupInfo;
    PROCESS_INFORMATION processInfo;

    if (!LogonUserW(
        userName.c_str(),
        domainName.c_str(),
        userPassword.c_str(),
        LOGON32_LOGON_INTERACTIVE,
        LOGON32_PROVIDER_DEFAULT,
        &hToken
    ))
    {
        status = GetLastError();
        std::wcout << L"ERROR: Cannot logon user with error: " << status << " => " << Win32ErrorToString(status) << std::endl;
        goto cleanup;
    }

    status = DsGetDcNameW(
        nullptr,
        domainName.c_str(),
        nullptr,
        nullptr,
        NULL,
        &pDomainControllerInfo
    );

    if (status != ERROR_SUCCESS)
    {
        status = DsGetDcNameW(
            nullptr,
            domainName.c_str(),
            nullptr,
            nullptr,
            DS_FORCE_REDISCOVERY,
            &pDomainControllerInfo
        );

        if (status != ERROR_SUCCESS)
        {
            status = HRESULT_FROM_WIN32(status);
            std::wcout << L"ERROR: Cannot find domain controller with error: " << status << " => " << Win32ErrorToString(status) << std::endl;
            goto cleanup;
        }
    }

    status = NetUserGetInfo(
        pDomainControllerInfo->DomainControllerName,
        userName.c_str(),
        4,
        reinterpret_cast<LPBYTE*>(&pUserInfo)
    );

    if (status != ERROR_SUCCESS)
    {
        status = HRESULT_FROM_WIN32(status);
        std::wcout << L"ERROR: Cannot get user info with error: " << status << " => " << Win32ErrorToString(status) << std::endl;
        goto cleanup;
    }

    pProfileInfo.dwSize = sizeof(pProfileInfo);
    pProfileInfo.lpUserName = const_cast<LPWSTR>(userAccount.c_str());
    pProfileInfo.dwFlags = PI_NOUI;
    pProfileInfo.lpProfilePath = pUserInfo->usri4_profile;

    if (!LoadUserProfileW(hToken, &pProfileInfo))
    {
        status = GetLastError();
        std::wcout << L"ERROR: Cannot user profile with error: " << status << " => " << Win32ErrorToString(status) << std::endl;
        goto cleanup;
    }

    if (!CreateEnvironmentBlock(&pEnvironmentBlock, hToken, false))
    {
        status = GetLastError();
        std::wcout << L"ERROR: Cannot create environment block with error: " << status << " => " << Win32ErrorToString(status) << std::endl;
        goto cleanup;
    }

    startupInfo.cb = sizeof(startupInfo);
    startupInfo.lpDesktop = const_cast<LPWSTR>(L"");

    if (!CreateProcessAsUserW(
        hToken,
        nullptr,
        const_cast<LPWSTR>(cmdLine.c_str()),
        nullptr,
        nullptr,
        false,
        CREATE_UNICODE_ENVIRONMENT,
        pEnvironmentBlock,
        nullptr,
        &startupInfo,
        &processInfo
    ))
    {
        status = GetLastError();
        std::wcout << L"ERROR: Cannot create process with error: " << status << " => " << Win32ErrorToString(status) << std::endl;
        goto cleanup;
    }
    else
    {
        std::wcout << L"!!! SUCCESS !!! => Waiting for child porcess to exist ..." << std::endl;

        status = WaitForSingleObject(processInfo.hProcess, INFINITE);
        if (status == WAIT_OBJECT_0)
        {
            if (!GetExitCodeProcess(processInfo.hProcess, &status))
            {
                status = GetLastError();
                std::wcout << L"ERROR: Failed to get exit status of child process with error: " << status << " => " << Win32ErrorToString(status) << std::endl;
            }
            else
            {
                std::wcout << L"Child process succesfully existed with exit code: " << status << " => " << Win32ErrorToString(status) << std::endl;
            }
        }
        else
        {
            std::wcout << L"Something went wrong while waiting on the child process to finish." << std::endl;
        }

        if (startupInfo.hStdError)
        {
            CloseHandle(startupInfo.hStdError);
            startupInfo.hStdError = NULL;
        }
        
        if (startupInfo.hStdInput)
        {
            CloseHandle(startupInfo.hStdInput);
            startupInfo.hStdInput = NULL;
        }

        if (startupInfo.hStdOutput)
        {
            CloseHandle(startupInfo.hStdOutput);
            startupInfo.hStdOutput = NULL;
        }

        CloseHandle(processInfo.hProcess);
        CloseHandle(processInfo.hThread);

        UnloadUserProfile(hToken, pProfileInfo.hProfile);
    }


cleanup:

    if (hToken)
    {
        CloseHandle(hToken);
        hToken = NULL;
    }

    if (pDomainControllerInfo)
    {
        NetApiBufferFree(pDomainControllerInfo);
        pDomainControllerInfo = nullptr;
    }

    if (pUserInfo)
    {
        NetApiBufferFree(pUserInfo);
        pUserInfo = nullptr;
    }

    if (pEnvironmentBlock)
    {
        DestroyEnvironmentBlock(pEnvironmentBlock);
        pEnvironmentBlock = nullptr;
    }

    return status;
}


