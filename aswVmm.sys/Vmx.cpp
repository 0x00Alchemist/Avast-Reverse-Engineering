__int64 __fastcall Vmx::VmmCall(__int64 vmmInput)
{
    __asm
    {
        mov     rax, rcx
        mov     rcx, rdx
        mov     rdx, r8
        vmmcall
        retn
    }
}

__int64 __fastcall Vmx::VmmCallHandler(__int64 vmxPtr, __int64 instrId, __int64 param1, __int64 param2)
{
  __int64 result;
  __int64 raxResult;
  void *retAddrPtr;
  __int64 index1;
  __int64 index2;

  result = Vmx::VmmCall(instrId);
  if ( result < 0 && vmxPtr && (result == 0xC000001D || result == 0xC0000096) )
  {
    *(vmxPtr + 528) = 1;
    *(vmxPtr + 536) = instrId;
    *(vmxPtr + 544) = param1;
    *(vmxPtr + 552) = param2;
    raxResult = 0x400000CAi64;
    __asm { cpuid }
    if ( *(vmxPtr + 528) )
    {
      *(vmxPtr + 528) = 0;
      _InterlockedExchangeAdd((vmxPtr + 604), 1u);
      retAddrPtr = Util::RetAddr();
      *(index2 + 16 * (index1 + 38)) = retAddrPtr;
      result = 0xC00000E5i64;
      *(index2 + 16 * index1 + 616) = 0xC00000E5;
    }
    else
    {
      return result;
    }
  }
  return result;
}

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

unsigned __int64 __fastcall Vmx::Vmxon(__int64 _RCX)
{
  __asm { vmxon   qword ptr [rcx] }
  return __readeflags();
}

unsigned __int64 Vmx::Vmxoff()
{
  __vmx_off();
  return __readeflags();
}
