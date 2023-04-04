unsigned __int64 __fastcall Vmx::VmWrite(__int64 vmRegister, __int64 value)
{
    __asm
    {
        vmwrite rcx, rdx
        pushfq
        pop     rax
        retn
    }
}

unsigned __int64 __fastcall Vmx::VmRead(__int64 Field, __int64 FieldValue)
{
    __asm
    {
        vmread  qword ptr [rdx], rcx
        pushfq
        pop     rax
        retn
    }
}