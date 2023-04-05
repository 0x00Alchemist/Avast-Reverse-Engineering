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