__int64 __fastcall Util::CalculateAverageCpuTime(unsigned int num_iterations, char use_first_min_only)
{
  unsigned int avgTimeDifference;
  unsigned int iterationCounter;
  unsigned __int64 startTimestamp;
  unsigned int currentTimeDifference;

  avgTimeDifference = -1;
  if ( *HvGlobalState->gap534 )
    return *HvGlobalState->gap534;
  if ( num_iterations )
  {
    if ( !use_first_min_only )
      startTimestamp = __rdtsc();
    for ( iterationCounter = 0; iterationCounter < num_iterations; ++iterationCounter )
    {
      if ( use_first_min_only )
        startTimestamp = __rdtsc();
      _RAX = 1i64;
      __asm { cpuid }
      if ( use_first_min_only )
      {
        currentTimeDifference = __rdtsc() - startTimestamp;
        if ( avgTimeDifference > currentTimeDifference )
          avgTimeDifference = currentTimeDifference;
      }
    }
    if ( !use_first_min_only )
      avgTimeDifference = (__rdtsc() - startTimestamp) / num_iterations;
    *HvGlobalState->gap534 = avgTimeDifference;
  }
  return avgTimeDifference;
}

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

__int64 __fastcall Util::RetrieveCpuidInformation(__int64 firstArg, __int64 secondArg, _DWORD *resultPtr)
{
  __int64 raxReg;
  __int64 result;
  __int64 rdxReg;
  __int64 rcxReg;
  __int64 rbxReg;

  raxReg = firstArg;
  __asm { cpuid }
  *resultPtr = result;
  resultPtr[1] = rbxReg;
  resultPtr[2] = rcxReg;
  resultPtr[3] = rdxReg;
  return result;
}

__int64 Util::GetStandardCpuInfo()
{
  if ( !sub_14002804E() )
    return 0i64;
  _RAX = 0i64;
  __asm { cpuid }
  if ( GenuineI == __PAIR64__(_RDX, _RBX) && ntel == _RCX )
    return 1i64;
  if ( Auth == _RBX && enti == _RDX && cAMD == _RCX )
    return 2i64;
  if ( Cent == _RBX && aurH == _RDX && auls == _RCX )
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

__int64 __fastcall Util::RdtscpWrapper(_DWORD *value, _DWORD *counter)
{
  __int64 result;

  __asm { rdtscp }
  *value = result;
  value[1] = counter;
  *counter = value;
  return result;
}

PVOID Util::FindSpecificDeviceFuncs()
{
  PVOID Addr; 
  struct _UNICODE_STRING DestinationString; 

  DestinationString = 0i64;
  RtlInitUnicodeString(&DestinationString, L"IoCreateDeviceSecure");
  IoCreateDeviceSecure = MmGetSystemRoutineAddress(&DestinationString);
  if ( !IoCreateDeviceSecure )
    IoCreateDeviceSecure = sub_140047124;
  RtlInitUnicodeString(&DestinationString, L"IoValidateDeviceIoControlAccess");
  Addr = MmGetSystemRoutineAddress(&DestinationString);
  IoValidateDeviceIoControlAccess = Addr;
  IsSpecificDeviceFuncsFound = 1;
  return Addr;
}

__int64 __fastcall Util::IoCreateDeviceSecureWrapper(
        PDRIVER_OBJECT DriverObject,
        unsigned int DeviceExtensionSize,
        _UNICODE_STRING *aswVmmDevice,
        unsigned int DeviceType,
        int DeviceCharacteristics,
        char Exclusive,
        _UNICODE_STRING *DeviceSDDLString,
        _GUID *DeviceClassGuid,
        PDEVICE_OBJECT DeviceObject)
{
  if ( !IsSpecificDeviceFuncsFound )
    Util::FindSpecificDeviceFuncs();
  return IoCreateDeviceSecure(
           DriverObject,
           DeviceExtensionSize,
           aswVmmDevice,
           DeviceType,
           DeviceCharacteristics,
           Exclusive,
           DeviceSDDLString,
           DeviceClassGuid,
           DeviceObject);
}

__int64 Util::FindSpecificHvFuncs()
{
  struct _UNICODE_STRING HalConvertDeviceIdtToIrql; 
  struct _UNICODE_STRING SeLocateProcessImageName; 
  struct _UNICODE_STRING KeRegisterNmiCallback; 
  struct _UNICODE_STRING KeDeregisterNmiCallback; 
  struct _UNICODE_STRING KeQueryUnbiasedInterruptTime; 
  struct _UNICODE_STRING ZwTraceControl; 
  struct _UNICODE_STRING NtTraceControl; 
  struct _UNICODE_STRING NtWaitForSingleObject; 

  *&HalConvertDeviceIdtToIrql.Length = 0x340032;
  HalConvertDeviceIdtToIrql.Buffer = L"HalConvertDeviceIdtToIrql";
  *&SeLocateProcessImageName.Length = 0x320030;
  SeLocateProcessImageName.Buffer = L"SeLocateProcessImageName";
  KeRegisterNmiCallback.Buffer = L"KeRegisterNmiCallback";
  KeDeregisterNmiCallback.Buffer = L"KeDeregisterNmiCallback";
  KeQueryUnbiasedInterruptTime.Buffer = L"KeQueryUnbiasedInterruptTime";
  ZwTraceControl.Buffer = L"ZwTraceControl";
  NtTraceControl.Buffer = L"NtTraceControl";
  NtWaitForSingleObject.Buffer = L"NtWaitForSingleObject";
  *&KeRegisterNmiCallback.Length = 0x2C002A;
  *&KeDeregisterNmiCallback.Length = 0x30002E;
  *&KeQueryUnbiasedInterruptTime.Length = 0x3A0038;
  *&ZwTraceControl.Length = 0x1E001C;
  *&NtTraceControl.Length = 0x1E001C;
  *&NtWaitForSingleObject.Length = 0x2C002A;
  *&HvGlobalState->gapEB8[8] = MmGetSystemRoutineAddress(&HalConvertDeviceIdtToIrql);
  *&HvGlobalState->gapEB8[16] = MmGetSystemRoutineAddress(&SeLocateProcessImageName);
  HvGlobalState->pfuncED0 = MmGetSystemRoutineAddress(&KeRegisterNmiCallback);
  HvGlobalState->qwordED8 = MmGetSystemRoutineAddress(&KeDeregisterNmiCallback);
  *HvGlobalState->gapEE0 = MmGetSystemRoutineAddress(&KeQueryUnbiasedInterruptTime);
  *&HvGlobalState->gapEE0[8] = MmGetSystemRoutineAddress(&ZwTraceControl);
  *&HvGlobalState->gapEE0[16] = MmGetSystemRoutineAddress(&NtTraceControl);
  *&HvGlobalState->gapEE0[24] = MmGetSystemRoutineAddress(&NtWaitForSingleObject);
  return 0i64;
}

__int64 __fastcall Util::MmQuery(struct _UNICODE_STRING *RegistryPath, _DWORD *hvDw134)
{
  NTSTATUS Status;
  NTSTATUS v4; 
  unsigned __int16 v5; 
  __int16 hwKey; 
  unsigned __int16 i;
  __int16 j; 
  __int64 v10; 
  WCHAR *KeyHandle; 
  __int128 KeyHandle_8; 
  __int128 P_8; 
  UNICODE_STRING String2; 
  UNICODE_STRING String1; 
  struct _RTL_QUERY_REGISTRY_TABLE QueryTable; 
  __int64 v17; 
  int v18; 
  __int128 v19; 
  __int128 v20; 
  __int64 v21; 
  struct _OBJECT_ATTRIBUTES ObjectAttributes; 
  struct _RTL_QUERY_REGISTRY_TABLE QueryTable_1; 
  __int64 v24; 
  int v25; 
  const wchar_t *v26; 
  __int128 *p_KeyHandle_8; 
  int v28; 
  __int64 v29; 
  int v30; 
  __int64 v31; 
  int v32; 
  __int128 v33; 
  __int128 v34; 
  __int64 v35; 

  QueryTable.Name = L"ImagePath";
  LODWORD(v10) = 0;
  QueryTable.EntryContext = &P_8;
  KeyHandle = 0i64;
  v21 = 0i64;
  QueryTable.QueryRoutine = 0i64;
  QueryTable_1.Name = L"VerifyDriverLevel";
  QueryTable_1.EntryContext = &v10;
  v26 = L"VerifyDrivers";
  p_KeyHandle_8 = &KeyHandle_8;
  QueryTable.Flags = 0x134;
  QueryTable.DefaultType = 0x1000000;
  QueryTable.DefaultData = 0i64;
  QueryTable.DefaultLength = 0;
  v17 = 0i64;
  v18 = 0;
  QueryTable_1.QueryRoutine = 0i64;
  QueryTable_1.Flags = 0x120;
  QueryTable_1.DefaultType = 0x4000000;
  QueryTable_1.DefaultData = 0i64;
  QueryTable_1.DefaultLength = 0;
  v24 = 0i64;
  v25 = 292;
  v28 = 0x1000000;
  v29 = 0i64;
  v30 = 0;
  v31 = 0i64;
  v32 = 0;
  v33 = 0i64;
  v34 = 0i64;
  v35 = 0i64;
  KeyHandle_8 = 0i64;
  P_8 = 0i64;
  v19 = 0i64;
  v20 = 0i64;
  if ( RegistryPath && hvDw134 )
  {
    ObjectAttributes.Length = 48;
    ObjectAttributes.RootDirectory = 0i64;
    ObjectAttributes.Attributes = 0x240;
    ObjectAttributes.ObjectName = RegistryPath;
    *&ObjectAttributes.SecurityDescriptor = 0i64;
    Status = ZwOpenKey(&KeyHandle, 0x20019u, &ObjectAttributes);
    if ( Status >= 0 )
    {
      v4 = RtlQueryRegistryValues(RTL_REGISTRY_HANDLE, KeyHandle, &QueryTable, 0i64, 0i64);
      Status = v4;
      if ( v4 >= 0
        || v4 == 0xC0000024
        && (QueryTable.DefaultType = 0x2000000,
            Status = RtlQueryRegistryValues(RTL_REGISTRY_HANDLE, KeyHandle, &QueryTable, 0i64, 0i64),
            Status >= 0) )
      {
        if ( !P_8 )
        {
LABEL_8:
          Status = 0xC0000225;
          goto LABEL_22;
        }
        v5 = P_8 >> 1;
        if ( P_8 >> 1 )
        {
          do
          {
            if ( *(*(&P_8 + 1) + 2i64 * v5 - 2) == 92 )
              break;
            --v5;
          }
          while ( v5 );
        }
        String1.Length = P_8 - 2 * v5;
        String1.MaximumLength = String1.Length;
        String1.Buffer = (*(&P_8 + 1) + 2i64 * v5);
        Status = RtlQueryRegistryValues(
                   RTL_REGISTRY_CONTROL,
                   L"Session Manager\\Memory Management",
                   &QueryTable_1,
                   0i64,
                   0i64);
        if ( Status >= 0 )
        {
          hwKey = KeyHandle_8;
          if ( !KeyHandle_8 )
            goto LABEL_8;
          if ( **(&KeyHandle_8 + 1) != 0x2A )
          {
            Status = 0xC0000225;
            i = 0;
            if ( (KeyHandle_8 & 0xFFFE) == 0 )
              goto LABEL_22;
            j = 0;
            while ( 1 )
            {
              String2.Length = hwKey - j;
              String2.MaximumLength = hwKey - j;
              String2.Buffer = (*(&KeyHandle_8 + 1) + 2i64 * i);
              if ( RtlPrefixUnicodeString(&String1, &String2, 1u) )
                break;
              hwKey = KeyHandle_8;
              ++i;
              j += RTL_REGISTRY_CONTROL;
              if ( i >= (KeyHandle_8 >> 1) )
                goto LABEL_22;
            }
          }
          Status = 0;
          *hvDw134 = v10;
        }
      }
    }
  }
  else
  {
    Status = 0xC000000D;
  }
LABEL_22:
  if ( *(&KeyHandle_8 + 1) )
    ExFreePoolWithTag(*(&KeyHandle_8 + 1), 0);
  if ( *(&P_8 + 1) )
    ExFreePoolWithTag(*(&P_8 + 1), 0);
  if ( KeyHandle )
    ZwClose(KeyHandle);
  return Status;
}