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

bool __fastcall Util::CheckDdiAvailability(ULONG Version)
{
  __int64 (__fastcall *SystemRoutineAddress)(_QWORD); 
  struct _UNICODE_STRING SystemRoutineName; 
  ULONG MajorVersion; 
  ULONG MinorVersion; 

  MajorVersion = 0;
  MinorVersion = 0;
  SystemRoutineName = 0i64;
  RtlInitUnicodeString(&SystemRoutineName, L"RtlIsNtDdiVersionAvailable");
  SystemRoutineAddress = MmGetSystemRoutineAddress(&SystemRoutineName);
  if ( SystemRoutineAddress )
    return SystemRoutineAddress(Version);
  if ( Version )
    return 0;
  PsGetVersion(&MajorVersion, &MinorVersion, 0i64, 0i64);
  return (MinorVersion + (MajorVersion << 8)) << 16 >= Version;
}

NTSTATUS __fastcall Util::CreateKlibCallback(int Ctx)
{
  struct _UNICODE_STRING DestinationString; 
  struct _OBJECT_ATTRIBUTES ObjectAttributes; 

  RtlInitUnicodeString(&DestinationString, aswKlibCallback[Ctx]);
  ObjectAttributes.RootDirectory = 0i64;
  ObjectAttributes.ObjectName = &DestinationString;
  ObjectAttributes.Length = 48;
  ObjectAttributes.Attributes = 0xC0;
  *&ObjectAttributes.SecurityDescriptor = 0i64;
  return ExCreateCallback(&Object, &ObjectAttributes, 0, 0);
}

__int64 Util::GetStandardCpuInfo()
{
  if ( !sub_14002804E() )
    return 0i64;
  _RAX = 0i64;
  __asm { cpuid }
  if ( qword_140031012 == __PAIR64__(_RDX, _RBX) && dword_14003101A == _RCX )
    return 1i64;
  if ( dword_14003101E == _RBX && dword_140031022 == _RDX && dword_140031026 == _RCX )
    return 2i64;
  if ( dword_14003102A == _RBX && dword_14003102E == _RDX && dword_140031032 == _RCX )
    return 3i64;
  else
    return 0i64;
}

void __fastcall Util::RegisterKlibCallback(PVOID CallbackContext, PVOID Argument1, PVOID Argument2)
{
  Util::CreateKlibCallback(CallbackContext);
  if ( qword_140045700 )
  {
    qword_140045700();
    qword_140045700 = 0i64;
  }
}

void Util::UnregisterCallback()
{
  if ( CallbackRegistration )
  {
    ExUnregisterCallback(CallbackRegistration);
    CallbackRegistration = 0i64;
  }
  if ( Object )
  {
    ObfDereferenceObject(Object);
    Object = 0i64;
  }
  if ( byte_140045690 )
    byte_140045690 = 0;
}

__int64 Utill::GetExtendedCpuInfo()
{
  int v0; 
  __int64 _RAX; 
  __int64 _RCX; 
  __int64 _RAX; 
  __int64 _RAX; 
  __int64 _RAX; 
  __int64 _RCX; 

  if ( sub_14002804E() )
  {
    v0 = Util::GetStandardCpuInfo();
    if ( v0 )
    {
      if ( v0 == 2 )
      {
        _RAX = 0x80000000i64;
        __asm { cpuid }
        if ( _RAX >= 0x80000001 )
        {
          _RAX = 0x80000001i64;
          __asm { cpuid }
          if ( (_RCX & 4) != 0 )
            return 1i64;
        }
      }
      else
      {
        _RAX = 1i64;
        __asm { cpuid }
        if ( (_RCX & 0x20) != 0 )
          return 1i64;
      }
    }
  }
  return 0i64;
}