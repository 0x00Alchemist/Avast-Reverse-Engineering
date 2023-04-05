__int64 __fastcall Vm::LoadState(__int64 state)
{
  __int64 load_result;

  load_result = state;
  __svm_vmload(state);
  return load_result;
}

__int64 __fastcall Vm::SaveState(__int64 state)
{
  __int64 savedState;

  savedState = state;
  __svm_vmsave(state);
  return savedState;
}



__int64 __fastcall Vm::Vmcall(__int64 command)
{
    __asm
    {
        mov     rax, rcx
        mov     rcx, rdx
        mov     rdx, r8
        vmcall
        retn
    }
}

__int64 __fastcall Vm::HandleVmCall(
        __int64 vmcall_result,
        __int64 status_code,
        __int64 parameter_one,
        __int64 parameter_two)
{
  __int64 function_result;
  __int64 _raxResult;
  void *return_address;
  __int64 _rdxIndex;
  __int64 _r8Base;

  function_result = Vm::Vmcall(status_code);
  if ( function_result < 0 && vmcall_result && (function_result == 0xC000001D || function_result == 0xC0000096) )
  {
    *(vmcall_result + 528) = 1;
    *(vmcall_result + 536) = status_code;
    *(vmcall_result + 544) = parameter_one;
    *(vmcall_result + 552) = parameter_two;
    _raxResult = 0x400000CAi64;
    __asm { cpuid }
    if ( *(vmcall_result + 528) )
    {
      *(vmcall_result + 528) = 0;
      _InterlockedExchangeAdd((vmcall_result + 604), 1u);
      return_address = Util::RetAddr();
      *(_r8Base + 16 * (_rdxIndex + 38)) = return_address;
      function_result = 0xC00000E5i64;
      *(_r8Base + 16 * _rdxIndex + 616) = 0xC00000E5;
    }
    else
    {
      return function_result;
    }
  }
  return function_result;
}

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