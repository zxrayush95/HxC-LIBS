
__int64 Func_UE4()
{
    return (rand() % 100) < 80;
}

bool IsFalsePositiveContext(void* ctx) {
    if (!ctx) return true;

    unsigned char* mem = reinterpret_cast<unsigned char*>(ctx);
    if (mem[0] == 0x90 && mem[1] == 0x90) // NOP NOP — common shellcode false positive
        return true;

    return false;
}


const char* xorEncryptString(const char* str, char key) {
    static char encrypted[256];
    int i = 0;
    while (str[i] != '\0') {
        encrypted[i] = str[i] ^ key;  // XOR each character
        i++;
    }
    encrypted[i] = '\0';
    return encrypted;
}

inline bool wrapperCheckValidString(const char* str) {
    return str && sub_4A2E7C((int64_t)str);
}

inline int64_t wrapperFunctionCall(__int64 a2, __int64 a1, const char* v6) {
    return (*(__int64 (__fastcall **)(__int64, _QWORD, const char *, const char *))(*(_QWORD *)a2 + 904LL))(
        a2,
        *(_QWORD *)(a1 + 16),
        v6,
        "(Ljava/lang/String;)V"
    );
}

inline void wrapperMemset(_BYTE* buffer, size_t size) {
    memset(buffer, 0, size);
}

inline void wrapperSnprintf(char* buffer, size_t size, const char* format, const char* a3) {
    snprintf(buffer, size, format, a3);
}

int64_t __fastcall sub_4CAD08(int64_t a1, int64_t a2, const char *a3) {
    const char *v6;
    int64_t v7;

    if (wrapperCheckValidString(a3)) {
        char xorKey = 0x5A;
        const char* sendCmd = xorEncryptString("sendCmd", xorKey);
        const char* sendCmdAlt = xorEncryptString("SendCmd", xorKey);

        if (*(_BYTE *)(a1 + 1))
            v6 = sendCmd;
        else
            v6 = sendCmdAlt;

        v7 = wrapperFunctionCall(a2, a1, v6);

        if (v7) {
            int64_t v8 = v7;
            if (!(*(unsigned __int8 (__fastcall **)(__int64))(*(_QWORD *)a2 + 1824LL))(a2)) {
                _BYTE v14[4096];

                wrapperMemset(v14, sizeof(v14));
                wrapperSnprintf((char*)v14, sizeof(v14), "mt:%s", a3);

                int64_t v9 = *(_QWORD *)a2;
                char* v10 = (char*)v14;
                int64_t v11 = a2;

                int64_t v12 = (*(__int64 (__fastcall **)(__int64, char *))(v9 + 1336))(v11, v10);

                if (!(*(unsigned __int8 (__fastcall **)(__int64))(*(_QWORD *)a2 + 1824LL))(a2)) {
                    return 0LL;
                }
            }
        }
    }

    return -1LL;
}


uintptr_t CalculateDynamicAddress() {
    return 0x1394C0;
}
void AdvancedCheck() {
    FILE *fp = fopen("/proc/self/status", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                int tracer_pid = atoi(line + 10);
                if (tracer_pid != 0) {
                    asm volatile ("mov x0, #0; svc #0x80");
                }
            }
        }
        fclose(fp);
    }
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
        asm volatile ("mov x0, #0; svc #0x80");
    }
    int status;
    pid_t pid = fork();
    if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
            _exit(0);
        }
        _exit(1);
    } else if (pid > 0) {
        waitpid(pid, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            asm volatile ("mov x0, #0; svc #0x80");
        }
    }
}
__int64 __fastcall C_Address(__int64 a1, __int64 a2, __int64 a3) {
    uintptr_t ret = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
    uintptr_t target_address = CalculateDynamicAddress();
    AdvancedCheck();
    if (rand() % 100 > 90) {
        usleep(rand() % 500000);
    }
    while (true) {
        if (ret == target_address) {
            int timeout = 3000000 + (rand() % 1000000);
            usleep(timeout);
        }
    }
}

__int64 __fastcall (*osub_1DDE64)(__int64 result, unsigned __int16 *a2);
__int64 __fastcall hsub_1DDE64(__int64 result, unsigned __int16 *a2){
  if ( a2 ){return 0;}else{
  return osub_1DDE64(result,a2);
  
   }
}

using sub_26BE00_t = void *(__fastcall *)(__int64, const void *, __int64, void **);
sub_26BE00_t osub_26BE00 = nullptr;

void *__fastcall hsub_26BE00(__int64 a1, const void *a2, __int64 a3, void **a4)
{
    if (!a2 || !a4 || !*a4 || a3 <= (__int64)a2)
        return *a4;

    __int64 size = (a3 - (__int64)a2) / 8;
    if (size <= 0 || size > 0x1000)
        return *a4;

    *a4 = (char *)*a4 - 8 * size;
    return memcpy(*a4, a2, 8 * size);
}


ZxR(_QWORD*, Monitor, (int* result, unsigned int a2))
{
    LOGI("GRD2| a2 : 0x%x", a2);
    if (a2 == 0x4) //GRD2
         return oMonitor(result, 5u);//DRD2
    else
        return oMonitor(result, a2);
}

ZxR(__int64, sub_265C1C, (__int64 a1, int a2))
{
	LOGI(oxorany("265"));
    return 0LL;
}	

ZxR(__int64, sub_265C1C, (__int64 a1, int a2))
{
	LOGI(oxorany("265"));
    return 0LL;
}	

using sub_24E33C_t = int(__fastcall*)(void* ctx);
sub_24E33C_t orig_24E33C = nullptr;

int __fastcall hooked_24E33C(void* ctx) {
    int result = orig_24E33C(ctx);

    if (result != 0) {
        // Check if context looks like a known false-positive (optional filtering)
        if (IsFalsePositiveContext(ctx)) {
         usleep((rand() % 3 + 1) * 1000); // 3 milliseconds
            return rand() % 2;
        }
        return 0; // Suppress actual detections safely
    }

    return result;
}

using sub_2A67F0_t = void(__fastcall*)(__int64, __int64, unsigned __int16, unsigned int);
sub_2A67F0_t orig_2A67F0 = nullptr;

void __fastcall hooked_2A67F0(__int64 a1, __int64 a2, unsigned __int16 a3, unsigned int a4)
{
    if (a3 >= 0x400 || !a2)
        return; 


    orig_2A67F0(a1, a2, a3, a4); 
}

void sub_3BAC98(__int64 a1) {
    if (!a1) return;
    *(float *)(a1 + 0x10) = 0.77f;
    *(float *)(a1 + 0x14) = 0.02f;
    *(float *)(a1 + 0x18) = 0.00f;
    for (int i = 0; i < 8; ++i) {
        *(int *)(a1 + 0x40 + (i * 4)) = 110 + i;
    }
    *(int *)(a1 + 0x30) = 1;
    *(int *)(a1 + 0x20) = 0;
    *(int *)(a1 + 0x24) = 1;
    *(long *)(a1 + 0x28) = (long)time(NULL);
}

__int64 __fastcall sub_24A064(int a1, const void *a2, unsigned __int16 a3, __int64 a4, unsigned __int64 a5, _QWORD *a6) {
    if ((unsigned int)(a3 + 2) + 8 >= 0x801 || *a6 + a3 > a5) {
        return -1;
    }

    memcpy((void *)(a4 + *a6), a2, a3);
    *a6 += a3;
    return 0;
}

__int64 __fastcall (*osub_2CA998)(__int64);

__int64 __fastcall hsub_2CA998(__int64 a1) {
    if ((*(_BYTE *)(a1 + 56) & 1) == 0)
        return 1;
    
    *(_BYTE *)(a1 + 56) = 0;
    *(_DWORD *)(a1 + 76) = 0;
    *(_DWORD *)(a1 + 80) = 0;
    
    return osub_2CA998(a1);  // optional for structure safety
}

__int64 __fastcall sub_28F070(__int64 a1, __int64 a2)
{
	__int64 Dummy = 0LL;		
  if (!a1 || !a2)
     return Dummy;
		
    __int64 result = 0;	
		return result;
}

__int64 __fastcall (*osub_1DD8B4)(__int64 a1, unsigned __int8 *a2, unsigned int a3);
__int64 __fastcall hsub_1DD8B4(__int64 a1, unsigned __int8 *a2, unsigned int a3)
{
 __int64 result; // x0
    __int64 v7; // x0
    __int64 v8; // x0
    __int64 v9; // x21
    _QWORD *v10; // xx
DWORD AnoBase = getAbsoluteAddress("libanogs.so",0x0);
auto ret = reinterpret_cast<uintptr_t>(__builtin_return_address(0)) - AnoBase;
LOGI("case 35 : a3 -> %zu", a3);
 if( a3 == 0x4E | a3 == 0x62 | a3 == 0x46 ){          
LOGI("case 35 BLOCKED : a3 -> 0x%lx", a3);
   return 0LL;
      }
   return osub_1DD8B4(a1,a2,a3);
}


void __fastcall sub_2CB354(__int64 a1) 
{
    if (!a1) return;

    int buffer_size = *(int *)(a1 + 76);
    void *buffer = *(void **)(a1 + 88);

    if (buffer_size > 0 && buffer) {
        memset(buffer, 0, buffer_size);
        *(int *)(a1 + 76) = 0;
        *(int *)(a1 + 80) = 0;
    }
}
__int64 __fastcall (*osub_347B1C)(__int64 a1, unsigned int a2);
__int64 __fastcall hsub_347B1C(__int64 a1, unsigned int a2) {
    	
	__int64 result = osub_347B1C(a1, a2);
	
    if ((a2 - 1001) < (9999 - 1001)) {
        a2 = 1337 + (a1 % 5); 
    }
    return result;
}


__int64 (__fastcall *osub_70D5FC0)(__int64 a1, _QWORD *a2, __int64 a3);
__int64 __fastcall hsub_70D5FC0(__int64 a1, _QWORD *a2, __int64 a3)
{__int64 result = osub_70D5FC0(a1, a2, a3);


    if (!a2) {return 0LL;}
    if (Func_UE4()) {return 0LL;}    
    return result;	
}


__int64 (__fastcall *osub_6004EFC)(__int64 a1);
__int64 __fastcall hsub_6004EFC(__int64 a1) {
    *(_BYTE *)(a1 + 382) = 1;
    *(_BYTE *)(a1 + 380) = 0;
    *(_BYTE *)(a1 + 381) = 0;

    __int64 result = osub_6004EFC(a1);

    *(_DWORD *)(a1 + 684) = 0;

    return result;
}


__int64 __fastcall sub_3742B8(_QWORD *a1) {return 1LL;}
void *Test_thread(void*) {
    LOGI(OBFUSCATE("MADEBY@ZxRTYREN"));
if (isGGAppPresentInExternalData()) {
        LOGI("ZxRTYREN");
		GGOX();
        return NULL;
    }	
    while (!isLibraryLoaded(targetLibName)) {
        sleep(1);
    }
HOOK_LIB_NO_ORIG("libanogs.so", "0x4CAD08", sub_4CAD08);        // Send CMD
HOOK_LIB_NO_ORIG("libanogs.so", "0x1394C0", C_Address);         // Crash Fix {.Socket}
HOOK_LIB("libanogs.so", "0x1DDE64", hsub_1DDE64, osub_1DDE64);  // Case {No.38}
HOOK_LIB("libanogs.so", "0x1DD8B4", hsub_1DD8B4, osub_1DD8B4);  // Case {No.35}
HOOK_LIB("libanogs.so", "0x26BE00", hsub_26BE00, osub_26BE00);  // Day Ban Fixer {.Offline}
//HOOK_LIB("libanogs.so", "0x175FD0", hsub_175FD0, osub_175FD0);  // Day Ban Fixer {.Online}
//HOOK_LIB("libanogs.so", "0x1A76A8", hsub_1A76A8, osub_1A76A8);
HOOK_LIB("libanogs.so", "0x4BF5BC", hMonitor, oMonitor);        // High Risk
HOOK_LIB("libanogs.so", "0x265C1C", hsub_265C1C, osub_265C1C);  // memcheck
HOOK_LIB("libanogs.so", "0x24E33C", hooked_24E33C, orig_24E33C);// __memcpy_chk
HOOK_LIB("libanogs.so", "0x2A67F0", hooked_2A67F0, orig_2A67F0);// __memcpy_chk
HOOK_LIB_NO_ORIG("libanogs.so", "0x3BAC98", sub_3BAC98);        // Memory Master
HOOK_LIB_NO_ORIG("libanogs.so", "0x24A064", sub_24A064);        // __memset_chk
HOOK_LIB_NO_ORIG("libanogs.so", "0x28F070", sub_28F070);        // Memory Master
HOOK_LIB("libanogs.so", "0x2CA998", hsub_2CA998, osub_2CA998);  
HOOK_LIB_NO_ORIG("libanogs.so", "0x2CB354", sub_2CB354);  
HOOK_LIB("libanogs.so", "0x347B1C", hsub_347B1C, osub_347B1C);  // Caller Imp Func.
HOOK_LIB_NO_ORIG("libanogs.so", "0x3742B8", sub_3742B8);        // Caller Imp Func.
PATCH_LIB("libanogs.so", "0x2B7A30", "00 00 80 D2 C0 03 5F D6");




PATCH_LIB("libanogs.so", "0x45FD4C", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x4600E4", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x49D8D0", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x4EBF7C", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x5056F0", "00 00 80 D2 C0 03 5F D6");



PATCH_LIB("libanogs.so", "0x2A6A10", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x1B67CC", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x139750", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x2C8AAC", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x2D3138", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x2D99DC", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x3997C8", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x4136C0", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x485320", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x485368", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x4853CC", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x496B4C", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x4D30E8", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x4D3334", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x4D3384", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x4DC8F8", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x5045F4", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x266004", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x2BC6B4", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x2D2A90", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x2D52B0", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x336C98", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x3601C4", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libanogs.so", "0x40085C", "00 00 80 D2 C0 03 5F D6");

PATCH_LIB("libUE4.so", "0x5FAAB44", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libUE4.so", "0x66874FC", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libUE4.so", "0xB194DE4", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libUE4.so", "0x3747F64", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libUE4.so", "0x381E22E", "00 00 80 D2 C0 03 5F D6");
PATCH_LIB("libUE4.so", "0x7147D28", "00 00 80 D2 C0 03 5F D6"); // RPC_ClientCoronaLab 3.8
PATCH_LIB("libUE4.so", "0x623C4F4", "00 00 80 D2 C0 03 5F D6"); // EditTargetRPC_ClientCoronaLab 3.8

HOOK_LIB("libUE4.so", "0x6004EFC", hsub_6004EFC, osub_6004EFC); // BulletHitInfo.37
HOOK_LIB("libUE4.so", "0x70D5FC0", hsub_70D5FC0, osub_70D5FC0); // Fake Damage.Fix


/*
if ( ZxRAYUSH ) { 
💠♾️Not Patched But These Are Ultra Private Hooks

HOOK_LIB_NO_ORIG("libUE4.so", "0x5B8CEFC", sub_5B8CEFC);        // UE4 ( anticheat.report )
HOOK_LIB_NO_ORIG("libUE4.so", "0x60F8860", sub_60F8860);        // UE4 ( WeaponDataManager )
}*/

PATCH_LIB("libUE4.so", "0x64E659C", "00 00 80 D2 C0 03 5F D6"); // ReportPlayerKillFlow
PATCH_LIB("libUE4.so", "0x64E64E4", "00 00 80 D2 C0 03 5F D6"); // ReportMrpcsFlow
PATCH_LIB("libUE4.so", "0x6594940", "00 00 80 D2 C0 03 5F D6"); // RPC_Client_ReportPlayerKillFlow
PATCH_LIB("libUE4.so", "0x6332B30", "00 00 80 D2 C0 03 5F D6"); // PlayerSecurityInfoCollector


	return NULL;
    }	
    