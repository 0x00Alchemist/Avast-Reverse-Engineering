unsigned __int64 Vm::Start()
{
    __asm
    {
        mov     rax, offset loc_1400281B5
        mov     rcx, 681Eh
        vmwrite rcx, rax
        jbe     short loc_1400281B1

        mov     rcx, 681Ch
        vmwrite rcx, rsp
        jbe     short loc_1400281B1

        pushfq
        pop     rax
        mov     rcx, 6820h
        vmwrite rcx, rax
        jbe     short loc_1400281B1

        vmlaunch

    loc_1400281B1:      
        pushfq
        pop     rax
        jmp     short locret_1400281B7

    loc_1400281B5:
        xor     eax, eax

    locret_1400281B7:
        retn
    }
}