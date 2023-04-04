__int64 __fastcall Util::AllocatePagedPoolWithTag(__int64 allocationSize, unsigned __int16 tagValue)
{
  PVOID allocatedPool;

  *allocationSize = 0;
  *(allocationSize + 2) = tagValue + 2;
  allocatedPool = ExAllocatePoolWithTag(PagedPool, tagValue + 2i64, 0x63557050u);
  *(allocationSize + 8) = allocatedPool;
  return allocatedPool == 0i64 ? 0xC000009A : 0;
}

void __fastcall Util::SetPageFaultAddress(unsigned __int64 pageFaultAddress)
{
  __writecr2(pageFaultAddress);
}

void* Util::RetAddr()
{
    __asm
    {
        mov     rax, [rsp+0]
        retn
    }
}

__int64 __fastcall Util::WriteDrRegister(__int64 value, char register_num, unsigned __int64 data, char control_bit)
{
  unsigned int retval;

  retval = 0;
  switch ( register_num )
  {
    case 0:
      __writedr(0, data);
      return retval;
    case 1:
      __writedr(1u, data);
      return retval;
    case 2:
      __writedr(2u, data);
      return retval;
    case 3:
      __writedr(3u, data);
      return retval;
    case 4:
      if ( !control_bit )
        return retval;
      goto LABEL_15;
    case 5:
      if ( !control_bit )
        return retval;
      goto LABEL_11;
    case 6:
LABEL_15:
      __writedr(6u, data);
      return retval;
  }
  if ( register_num != 7 )
    return 0xC000000D;
LABEL_11:
  if ( (Vmx::VmWrite(0x681Ai64, data) & 0x41) != 0 )
    __debugbreak();
  return retval;
}

__int64 __fastcall Util::ReadDrRegister(__int64 param1, char registerIdx, unsigned __int64 *destPtr, char ignoreFlag)
{
  unsigned int retVal;
  unsigned __int64 tempValue;
  unsigned __int64 regValue;

  retVal = 0;
  switch ( registerIdx )
  {
    case 0:
      regValue = __readdr(0);
      *destPtr = regValue;
      return retVal;
    case 1:
      tempValue = __readdr(1u);
      goto LABEL_21;
    case 2:
      tempValue = __readdr(2u);
      goto LABEL_21;
    case 3:
      tempValue = __readdr(3u);
      goto LABEL_21;
    case 4:
      tempValue = __readdr(6u);
      if ( !ignoreFlag )
        tempValue = 0i64;
      goto LABEL_21;
    case 5:
      if ( !ignoreFlag )
      {
        *destPtr = 0i64;
        return retVal;
      }
      goto LABEL_10;
    case 6:
      tempValue = __readdr(6u);
LABEL_21:
      *destPtr = tempValue;
      return retVal;
  }
  if ( registerIdx != 7 )
    return 0xC000000D;
LABEL_10:
  if ( (Vmx::VmRead(26650i64, destPtr) & 0x41) != 0 )
    __debugbreak();
  return retVal;
}