unsigned __int64 __fastcall Hypervisor::AsmInvept(int _ECX, __int64 _RDX)
{
    __asm
    {
        invept  ecx, xmmword ptr [rdx]
        pushfq
        pop     rax
        retn
    }
}

unsigned __int64 __fastcall Hypervisor::AsmGetVpidState(int _ECX, __int64 _RDX)
{
    __asm
    {
        invvpid ecx, xmmword ptr [rdx]
        pushfq
        pop     rax
        retn
    }
}

void Hypervisor::AsmLoadCxIntoLdt(__int16 _CX)
{
    __asm
    {
        lldt    cx
        retn
    }
}

void Hypervisor::AsmGetGDTInfo(void* gdtInfo)
{
    __asm 
    {
        sgdt    fword ptr [rcx]
        retn
    }
}

void Hypervisor::AsmGetSystemInterruptTable(void* interruptTable)
{
    __asm
    {
        sidt    fword ptr [rcx]
        retn
    }
}

__int16 Hypervisor::AsmGetDataSegment()
{
    __asm
    {
        mov ax, ds
        retn
    }
}

__int16 Hypervisor::AsmGetExtraSegment()
{
    __asm
    {
        mov ax, es
        retn
    }
}

__int16 Hypervisor::AsmGetCodeSegment()
{
    __asm
    {
        mov ax, cs
        retn
    }
}

__int16 Hypervisor::AsmGetStackSegment()
{
    __asm
    {
        mov ax, ss
        retn
    }
}

__int16 Hypervisor::AsmGetFSRegister()
{
    __asm
    {
        mov ax, fs
        retn
    }
}

__int16 Hypervisor::AsmGetGlobalSegment()
{
    __asm
    {
        mov ax, gs
        retn
    }
}

__int16 Hypervisor::AsmGetLdtSegment()
{
    __asm
    {
        sldt ax
        retn
    }
}

void Hypervisor::AsmInvd()
{
  __asm { invd }
}

void __fastcall Hypervisor::AsmLoadGDT(void *Src)
{
  __lgdt(Src);
}

void __fastcall Hypervisor::AsmLoadIDT(void *Src)
{
  __lidt(Src);
}

__int16 Hypervisor::AsmStr()
{
  __int16 result; 

  __asm { str     ax }
  return result;
}

__int64 __fastcall Hypervisor::AsmXgetbv(__int64 a1, __int64 a2)
{
  __int64 v2; 

  __asm { xgetbv }
  return (a2 << 32) | v2;
}

void Hypervisor::AsmLtr()
{
  __asm { ltr     cx }
}
