#include <iostream>
#include <Windows.h>
#include <UserEnv.h>
#include <dsgetdc.h>
#include <Lm.h>

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "userenv.lib")

HANDLE g_hStopEvent = NULL;
HANDLE g_hProcess = NULL;

bool WINAPI ConsoleHandler(DWORD signal)
{
    if (signal == CTRL_C_EVENT ||
        signal == CTRL_CLOSE_EVENT ||
        signal == CTRL_BREAK_EVENT ||
        signal == CTRL_LOGOFF_EVENT ||
        signal == CTRL_SHUTDOWN_EVENT
        )
    {
        TerminateProcess(g_hProcess, S_OK);
        SetEvent(g_hStopEvent);
    }

    return true;
}

void PrintWin32ErrorToString(LPCWSTR szMessage, DWORD dwErr)
{
    const int maxSite = 512;
    const LPCWSTR szFormat = L" hex: 0x%x dec: %d message: %s\n";
    LPCWSTR szDefaultMessage = L"<< unknown message for this error code >>";
    WCHAR wszMsgBuff[maxSite];
    DWORD dwChars;
    HINSTANCE hInst = NULL;

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
        hInst = LoadLibraryW(L"Ntdsbmsg.dll");
        if (!hInst)
        {
            wprintf(szFormat, dwErr, dwErr, szDefaultMessage);
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

        if (hInst)
        {
            FreeLibrary(hInst);
            hInst = NULL;
        }
    }

    wprintf(szFormat, dwErr, dwErr, (dwChars ? wszMsgBuff : szDefaultMessage));
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
        PrintWin32ErrorToString(L"ERROR: Cannot logon user with error:", status);
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
            PrintWin32ErrorToString(L"ERROR: Cannot find domain controller with error:", status);
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
        PrintWin32ErrorToString(L"ERROR: Cannot get user info with error:", status);
        goto cleanup;
    }

    ZeroMemory(&pProfileInfo, sizeof(pProfileInfo));
    pProfileInfo.dwSize = sizeof(pProfileInfo);
    pProfileInfo.lpUserName = const_cast<LPWSTR>(userAccount.c_str());
    pProfileInfo.dwFlags = PI_NOUI;
    pProfileInfo.lpProfilePath = pUserInfo->usri4_profile;

    if (!LoadUserProfileW(hToken, &pProfileInfo))
    {
        status = GetLastError();
        PrintWin32ErrorToString(L"ERROR: Cannot user profile with error:", status);
        goto cleanup;
    }

    if (!CreateEnvironmentBlock(&pEnvironmentBlock, hToken, false))
    {
        status = GetLastError();
        PrintWin32ErrorToString(L"ERROR: Cannot create environment block with error:", status);
        goto cleanup;
    }

    ZeroMemory(&startupInfo, sizeof(startupInfo));
    startupInfo.cb = sizeof(startupInfo);
    startupInfo.lpDesktop = const_cast<LPWSTR>(L"");

    ZeroMemory(&processInfo, sizeof(processInfo));

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
        status = HRESULT_FROM_WIN32(GetLastError());
        PrintWin32ErrorToString(L"ERROR: Cannot create process with error:", status);
        goto cleanup;
    }
    else
    {
        std::wcout << L"!!! SUCCESS !!! => Waiting (forever) for child porcess to exit ..." << std::endl;

        g_hProcess = processInfo.hProcess;

        g_hStopEvent = CreateEventW(NULL, true, false, nullptr);
        if (!g_hStopEvent)
        {
            status = GetLastError();
            PrintWin32ErrorToString(L"ERROR: Failed to create event with error:", status);
            goto cleanup;
        }

        if (!SetConsoleCtrlHandler(reinterpret_cast<PHANDLER_ROUTINE>(ConsoleHandler), true))
        {
            status = GetLastError();
            PrintWin32ErrorToString(L"ERROR: Could not set control handler with error:", status);
            goto cleanup;
        }

        std::wcout << L"\tAlso waiting for \"CTRL+C\" to (force) terminate the child process and finish the program (just in case it has no UI or you can't see it for some reason) ..." << std::endl;
        std::wcout << L"\tIf you are using a tool like PsExec.exe (or similar) to start this RunAs tool (program/exe), then, if you press \"CTRL+C\"," << std::endl;
        std::wcout << L"it will terminate without being able to close the child process in some situations (running under gMSA for example) and so, " << std::endl;
        std::wcout << L"it might be that you need to kill the child process manually - PID of the child process is: " << processInfo.dwProcessId << std::endl;

        const int waitHandleCount = 2;
        HANDLE hWaitForHandles[waitHandleCount];
        hWaitForHandles[0] = processInfo.hProcess;
        hWaitForHandles[1] = g_hStopEvent;

        status = WaitForMultipleObjects(waitHandleCount, hWaitForHandles, false, INFINITE);
        if (status == WAIT_OBJECT_0)
        {
            if (!GetExitCodeProcess(processInfo.hProcess, &status))
            {
                status = GetLastError();
                PrintWin32ErrorToString(L"ERROR: Failed to get exit status of child process with error:", status);
            }
            else
            {
                PrintWin32ErrorToString(L"Child process succesfully existed with exit code:", status);
            }
        }
        else if (status == (WAIT_OBJECT_0 + 1))
        {
            std::wcout << L"Cancel event (Ctrl+C) was pressed, so it \"killed\" the child process and thus the exit status is irrelevant." << std::endl;
        }
        else
        {
            std::wcout << L"Something went wrong while waiting on the child process to finish. This can be ignored in this case though ..." << std::endl;
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

    if (g_hStopEvent)
    {
        CloseHandle(g_hStopEvent);
        g_hStopEvent = NULL;
    }

    return status;
}
