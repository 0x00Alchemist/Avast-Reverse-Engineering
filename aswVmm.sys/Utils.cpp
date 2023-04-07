char *__fastcall Util::GetModuleBaseAddress(
        const char *moduleName,
        unsigned __int64 searchAddress,
        _OWORD *bufferPointer)
{
  __int64 baseAddressResult;
  char *result;
  char *allocatedBuffer;
  ULONG counterValue;
  __int64 iterationCounter;
  _OWORD *localBufferPointer;
  __int64 moduleBaseOffset;
  char *tempBufferLength;
  __int64 v11;
  char *v12;
  __int64 v13;
  _OWORD *v14;
  char *v15;
  __int64 v16;
  ULONG ReturnLength[2];
  __int64 v18;
  char *v19;

  baseAddressResult = 0i64;
  v19 = 0i64;
  ReturnLength[0] = 0;
  ZwQuerySystemInformation(SystemModuleInformation, ReturnLength, 0, ReturnLength);
  if ( !ReturnLength[0] )
    return 0i64;
  result = ExAllocatePoolWithTag(PagedPool, 2 * ReturnLength[0], 'yDpS');
  allocatedBuffer = result;
  v19 = result;
  if ( result )
  {
    sub_1400296C0(result, 0, 2 * ReturnLength[0]);
    if ( ZwQuerySystemInformation(SystemModuleInformation, allocatedBuffer, 2 * ReturnLength[0], ReturnLength) >= 0 )
    {
      counterValue = 0;
      iterationCounter = 2i64;
      localBufferPointer = bufferPointer;
      while ( 1 )
      {
        ReturnLength[1] = counterValue;
        if ( counterValue >= *allocatedBuffer )
          break;
        moduleBaseOffset = 0x128i64 * counterValue;
        if ( searchAddress )
        {
          if ( searchAddress >= *&allocatedBuffer[moduleBaseOffset + 24] )
          {
            v13 = 296i64 * counterValue;
            if ( searchAddress < *&allocatedBuffer[v13 + 24] + *&allocatedBuffer[v13 + 32] )
            {
              baseAddressResult = *&allocatedBuffer[v13 + 24];
              v18 = baseAddressResult;
              if ( bufferPointer )
              {
                v14 = bufferPointer;
                v15 = &allocatedBuffer[v13 + 8];
                v16 = 2i64;
                do
                {
                  *v14 = *v15;
                  v14[1] = *(v15 + 1);
                  v14[2] = *(v15 + 2);
                  v14[3] = *(v15 + 3);
                  v14[4] = *(v15 + 4);
                  v14[5] = *(v15 + 5);
                  v14[6] = *(v15 + 6);
                  v14 += 8;
                  *(v14 - 1) = *(v15 + 7);
                  v15 += 128;
                  --v16;
                }
                while ( v16 );
                *v14 = *v15;
                v14[1] = *(v15 + 1);
                *(v14 + 4) = *(v15 + 4);
              }
            }
          }
        }
        else
        {
          if ( !moduleName )
          {
            baseAddressResult = *&allocatedBuffer[moduleBaseOffset + 24];
            v18 = baseAddressResult;
            if ( bufferPointer )
            {
              tempBufferLength = &allocatedBuffer[296 * counterValue + 8];
              do
              {
                *localBufferPointer = *tempBufferLength;
                localBufferPointer[1] = *(tempBufferLength + 1);
                localBufferPointer[2] = *(tempBufferLength + 2);
                localBufferPointer[3] = *(tempBufferLength + 3);
                localBufferPointer[4] = *(tempBufferLength + 4);
                localBufferPointer[5] = *(tempBufferLength + 5);
                localBufferPointer[6] = *(tempBufferLength + 6);
                localBufferPointer += 8;
                *(localBufferPointer - 1) = *(tempBufferLength + 7);
                tempBufferLength += 128;
                --iterationCounter;
              }
              while ( iterationCounter );
              *localBufferPointer = *tempBufferLength;
              localBufferPointer[1] = *(tempBufferLength + 1);
              *(localBufferPointer + 4) = *(tempBufferLength + 4);
            }
            break;
          }
          v11 = 296i64 * counterValue;
          if ( !stricmp(&allocatedBuffer[v11 + 48 + *&allocatedBuffer[moduleBaseOffset + 46]], moduleName) )
          {
            if ( bufferPointer )
            {
              v12 = &allocatedBuffer[v11 + 8];
              do
              {
                *localBufferPointer = *v12;
                localBufferPointer[1] = *(v12 + 1);
                localBufferPointer[2] = *(v12 + 2);
                localBufferPointer[3] = *(v12 + 3);
                localBufferPointer[4] = *(v12 + 4);
                localBufferPointer[5] = *(v12 + 5);
                localBufferPointer[6] = *(v12 + 6);
                localBufferPointer += 8;
                *(localBufferPointer - 1) = *(v12 + 7);
                v12 += 128;
                --iterationCounter;
              }
              while ( iterationCounter );
              *localBufferPointer = *v12;
              localBufferPointer[1] = *(v12 + 1);
              *(localBufferPointer + 4) = *(v12 + 4);
            }
            baseAddressResult = *&allocatedBuffer[v11 + 24];
            v18 = baseAddressResult;
            break;
          }
        }
        ++counterValue;
      }
    }
    if ( allocatedBuffer )
      ExFreePoolWithTag(allocatedBuffer, 'yDpS');
    return baseAddressResult;
  }
  return result;
}

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

char Util::GetProcessorFamily()
{
  char v0;
  unsigned __int32 ProcessorFamily; 
  int v2; 
  unsigned __int32 v3; 
  int v4; 
  int v5; 

  v0 = 0;
  ProcessorFamily = EAX(__cpuid(1, 0));
  v2 = (ProcessorFamily >> 8) & 0xF;
  v3 = ProcessorFamily;
  HvGlobalState->dwordEB0 = v2;
  if ( v2 == 15 )
    HvGlobalState->dwordEB0 += (ProcessorFamily >> 20);
  v4 = ProcessorFamily & 0xF00;
  if ( (v3 & 0xF00) == 0xF00 || v4 == 0x600 )
    v5 = (v3 >> 4) + ((v3 >> 12) & 0xF0);
  else
    v5 = v3 >> 4;
  HvGlobalState->dwordEB4 = v5;
  *HvGlobalState->gapEB8 = v3 & 0xF;
  if ( HvGlobalState->dwordEB0 == 15 )
    return HvGlobalState->dwordEB4 <= 6u;
  return v0;
}

__int64 Util::GetSpecificInfo()
{
  unsigned int Status;
  int v1;
  int v2;
  __int16 SvmSubfeature;
  __int64 SvmInfo;
  int v5;
  int v6;
  unsigned int v7;
  int v8;

  Status = 0;
  if ( HvGlobalState->byte150 && (v1 = HvGlobalState->dword158) != 0 )
  {
    v2 = v1 - 1;
    if ( v2 )
    {
      if ( v2 == 1 )
      {
        SvmInfo = __cpuid(0x8000000A, 0);
        SvmSubfeature = EDX(SvmInfo);
        HIDWORD(HvGlobalState[1].qword0) = EBX(SvmInfo); // Probably number of ASIDs
        if ( (SvmSubfeature & 1) != 0 )
          HvGlobalState->dword1338 |= 1u;
        if ( (SvmSubfeature & 2) != 0 )
          HvGlobalState->dword1338 |= 2u;
        if ( (SvmSubfeature & 8) != 0 )
          HvGlobalState->dword1338 |= 0x10u;
        if ( (SvmSubfeature & 0x40) != 0 )
          HvGlobalState->dword1338 |= 0x20u;
        if ( (SvmSubfeature & 0x80u) != 0 )
          HvGlobalState->dword1338 |= 4u;
        if ( (SvmSubfeature & 0x2000) != 0 )
          HvGlobalState->dword1338 |= 0x40u;
        if ( (SvmSubfeature & 0x8000) != 0 )
          HvGlobalState->dword1338 |= 0x80u;
        if ( (EDX(__cpuid(0x80000001, 0)) & 0x4000000) != 0 ) // Specific features
          HvGlobalState->dword1338 |= 8u;
        if ( HvGlobalState->dwordEB0 == 15 )
        {
          v5 = HvGlobalState->dwordEB4;
          if ( (v5 - 104) > 23 || (v6 = 0x800009, !_bittest(&v6, v5 - 104)) || !*HvGlobalState->gapEB8 )
          {
            v7 = v5 - 108;
            if ( (v5 - 108) > 16 || (v8 = 0x10009, !_bittest(&v8, v7)) || *HvGlobalState->gapEB8 < 2u )
              LOBYTE(HvGlobalState[1].qword0) = 1;
          }
        }
      }
    }
    else
    {
      return Util::GetVmxFeatures();
    }
  }
  else
  {
    return 0xC00000BB;
  }
  return Status;
}

__int64 Util::GetVmxFeatures()
{
  __int64 _RAX; 
  __int64 _RAX; 
  __int64 _RAX; 
  __int64 _RAX; 
  unsigned __int64 VmxBasicValue; 
  __int64 VmxProcBasedCtls; 
  unsigned __int64 VmxProcbasedCtls2; 
  unsigned __int64 HiVmxProcbasedCtls2; 
  unsigned __int64 VmxEPTVpidCap; 
  unsigned __int64 VmxEPTVpidCap_1;
  unsigned __int64 VmxEntryCtls; 
  unsigned __int64 VmxCr4Fixed1; 
  unsigned __int8 PeMoInfo; 
  int CpuExtensions; 
  int v21; 

  _RAX = 0i64;
  __asm { cpuid }
  if ( _RAX >= 7 )
  {
    Util::RetrieveCpuidInformation(7i64, 0i64, &CpuExtensions);
    if ( (v21 & 0x400) != 0 )
      HvGlobalState->dword1338 |= 0x100000u;
  }
  _RAX = 0xAi64;
  __asm { cpuid }
  PeMoInfo = _RAX;
  LOBYTE(HvGlobalState[1].osversioninfow18.szCSDVersion[54]) = 1;
  VmxBasicValue = __readmsr(MSR_IA32_VMX_BASIC);
  if ( (VmxBasicValue & 0x80000000000000i64) != 0 )
  {
    *&HvGlobalState[1].osversioninfow18.szCSDVersion[4] = MSR_IA32_VMX_TRUE_PINBASED_CTLS;
    *&HvGlobalState[1].osversioninfow18.szCSDVersion[6] = MSR_IA32_VMX_TRUE_PROCBASED_CTLS;
    *&HvGlobalState[1].osversioninfow18.szCSDVersion[8] = MSR_IA32_VMX_TRUE_EXIT_CTLS;
    *&HvGlobalState[1].osversioninfow18.szCSDVersion[10] = MSR_IA32_VMX_TRUE_ENTRY_CTLS;
  }
  else
  {
    *&HvGlobalState[1].osversioninfow18.szCSDVersion[4] = MSR_IA32_VMX_PINBASED_CTLS;
    *&HvGlobalState[1].osversioninfow18.szCSDVersion[6] = MSR_IA32_VMX_PROCBASED_CTLS;
    *&HvGlobalState[1].osversioninfow18.szCSDVersion[8] = MSR_IA32_VMX_EXIT_CTLS;
    *&HvGlobalState[1].osversioninfow18.szCSDVersion[10] = MSR_IA32_VMX_ENTRY_CTLS;
  }
  VmxProcBasedCtls = __readmsr(*&HvGlobalState[1].osversioninfow18.szCSDVersion[6]);
  if ( (VmxProcBasedCtls & 0x8000) == 0 )
    HvGlobalState->dword1338 |= 0x200000u;
  if ( VmxProcBasedCtls < 0 )
  {
    HvGlobalState->dword1338 |= 0x80000000;
    VmxProcbasedCtls2 = __readmsr(MSR_IA32_VMX_PROCBASED_CTLS2);
    HiVmxProcbasedCtls2 = HIDWORD(VmxProcbasedCtls2);
    if ( (VmxProcbasedCtls2 & 0x2000000000i64) != 0 )
    {
      VmxEPTVpidCap = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);
      if ( (VmxEPTVpidCap & 0x100000000i64) != 0 )
      {
        HvGlobalState->dword1338 |= 4u;
        if ( (VmxEPTVpidCap & 0x10000000000i64) != 0 )
          HvGlobalState->dword1338 |= 0x10000u;
        if ( (VmxEPTVpidCap & 0x20000000000i64) != 0 )
          HvGlobalState->dword1338 |= 0x20000u;
        if ( (VmxEPTVpidCap & 0x40000000000i64) != 0 )
          HvGlobalState->dword1338 |= 0x40000u;
        if ( (VmxEPTVpidCap & 0x80000000000i64) != 0 )
          HvGlobalState->dword1338 |= 0x80000u;
      }
    }
    if ( (HiVmxProcbasedCtls2 & 0x80u) != 0i64 )
      HvGlobalState->dword1338 |= 1u;
    if ( (HiVmxProcbasedCtls2 & 4) != 0 )
      HvGlobalState->dword1338 |= 2u;
    if ( (HiVmxProcbasedCtls2 & 0x4000) != 0 )
      HvGlobalState->dword1338 |= 0x8000u;
    if ( (HiVmxProcbasedCtls2 & 2) != 0 )
    {
      VmxEPTVpidCap_1 = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);
      if ( (VmxEPTVpidCap_1 & 0x100040) == 0x100040 )
      {
        HvGlobalState->dword1338 |= 8u;
        if ( (VmxEPTVpidCap_1 & 1) != 0 )
          HvGlobalState->dword1338 |= 0x200u;
        if ( (VmxEPTVpidCap_1 & 0x100) != 0 )
          HvGlobalState->dword1338 |= 0x40u;
        if ( (VmxEPTVpidCap_1 & 0x4000) != 0 )
          HvGlobalState->dword1338 |= 0x80u;
        if ( (VmxEPTVpidCap_1 & 0x10000) != 0 )
          HvGlobalState->dword1338 |= 0x20u;
        if ( (VmxEPTVpidCap_1 & 0x20000) != 0 )
          HvGlobalState->dword1338 |= 0x10u;
        if ( (VmxEPTVpidCap_1 & 0x200000) != 0 )
          HvGlobalState->dword1338 |= 0x100u;
        if ( (VmxEPTVpidCap_1 & 0x2000000) != 0 )
          HvGlobalState->dword1338 |= 0x1000u;
        if ( (VmxEPTVpidCap_1 & 0x4000000) != 0 )
          HvGlobalState->dword1338 |= 0x2000u;
      }
    }
  }
  VmxEntryCtls = __readmsr(*&HvGlobalState[1].osversioninfow18.szCSDVersion[10]) >> 32;
  if ( (VmxEntryCtls & 0x2000) != 0 && PeMoInfo >= 2u )
    HvGlobalState->dword1338 |= 0x4000u;
  if ( (VmxEntryCtls & 0x4000) != 0 )
    HvGlobalState->dword1338 |= 0x400u;
  if ( (VmxEntryCtls & 0x8000) != 0 )
    HvGlobalState->dword1338 |= 0x800u;
  if ( (VmxEntryCtls & 0x20000) != 0 )
    HvGlobalState->dword1338 |= 0x1000000u;
  if ( (VmxEntryCtls & 0x40000) != 0 )
    HvGlobalState->dword1338 |= 0x2000000u;
  if ( (VmxEntryCtls & 0x200000) != 0 )
    HvGlobalState->dword1338 |= 0x4000000u;
  if ( (__readmsr(MSR_IA32_VMX_MISC) & 0x20000000) != 0 )
    HvGlobalState->dword1338 |= 0x400000u;
  if ( (__readmsr(*&HvGlobalState[1].osversioninfow18.szCSDVersion[4]) & 0x4000000000i64) != 0 ) // Pinbased Ctls
    HvGlobalState->dword1338 |= 0x800000u;
  *(&HvGlobalState[1].qword0 + 4) = __readmsr(MSR_IA32_VMX_BASIC);
  *(&HvGlobalState[1].punicode_string8 + 4) = __readmsr(MSR_IA32_VMX_MISC);
  *&HvGlobalState[1].gap10[4] = __readmsr(MSR_IA32_VMX_CR0_FIXED0);
  *&HvGlobalState[1].osversioninfow18.dwMajorVersion = __readmsr(MSR_IA32_VMX_CR0_FIXED1);
  *&HvGlobalState[1].osversioninfow18.dwBuildNumber = __readmsr(MSR_IA32_VMX_CR4_FIXED0);
  VmxCr4Fixed1 = __readmsr(MSR_IA32_VMX_CR4_FIXED1);
  *HvGlobalState[1].osversioninfow18.szCSDVersion = (HIDWORD(VmxCr4Fixed1) << 32) | VmxCr4Fixed1;
  return 0i64;
}

char __fastcall Util::ProcessorFamilyWrapper(__int64 a1, __int64 a2)
{
  unsigned __int32 ProcessorFamily; 
  int v3;
  int v4; 

  LOBYTE(a2) = 0;
  if ( HvGlobalState->dword158 == 1 )
  {
    LOBYTE(a2) = (Util::GetProcessorFamily)((HvGlobalState->dword158 - 1), a2);
  }
  else if ( HvGlobalState->dword158 == 2 )
  {
    ProcessorFamily = EAX(__cpuid(1, 0));
    v3 = (ProcessorFamily >> 8) & 0xF;
    HvGlobalState->dwordEB0 = v3;
    if ( v3 == 15 )
      HvGlobalState->dwordEB0 += (ProcessorFamily >> 20);
    v4 = ProcessorFamily >> 4;
    if ( v3 == 15 )
      HvGlobalState->dwordEB4 = v4 + ((ProcessorFamily >> 12) & 0xF0);
    else
      HvGlobalState->dwordEB4 = v4;
    *HvGlobalState->gapEB8 = ProcessorFamily & 0xF;
    LOBYTE(a2) = HvGlobalState->dwordEB0 == 15;
  }
  return a2;
}

__int64 __fastcall Util::QueryConfigStrings(void *IoBlockPtr, struct _UNICODE_STRING *ConfigString, char **RetPool)
{
  NTSTATUS ValueKey; 
  char *PoolWithTag; 
  char *Pool; 
  void *RetAddr; 
  int v7; 
  __int64 v8; 
  ULONG ResultLength[6]; 

  ResultLength[0] = 0;
  if ( IoBlockPtr )
  {
    ValueKey = ZwQueryValueKey(IoBlockPtr, ConfigString, KeyValuePartialInformation, 0i64, 0, ResultLength);
    if ( ValueKey == 0xC0000023 )
    {
      PoolWithTag = ExAllocatePoolWithTag(PagedPool, ResultLength[0] + 6i64, 'MMVA');
      Pool = PoolWithTag;
      if ( PoolWithTag )
      {
        sub_1400296C0(PoolWithTag, 0, ResultLength[0] + 6i64);
        ValueKey = ZwQueryValueKey(
                     IoBlockPtr,
                     ConfigString,
                     KeyValuePartialInformation,
                     Pool,
                     ResultLength[0],
                     ResultLength);
        if ( ValueKey < 0 )
          ExFreePoolWithTag(Pool, 'MMVA');
        else
          *RetPool = Pool;
      }
      else
      {
        ValueKey = 0xC0000017;
        _InterlockedExchangeAdd(HvGlobalState->gapF30, 1u);
        RetAddr = Util::RetAddr();
        *&HvGlobalState->gapF30[16 * v7 + 8] = RetAddr;
        *&HvGlobalState->gapF30[16 * v8 + 16] = 0xC0000017;
      }
    }
  }
  else
  {
    return 0xC000000D;
  }
  return ValueKey;
}

NTSTATUS __fastcall Util::RegistryCheck(void **Data, char SpecificAccess, char IsValueExists, ULONG *Disposition)
{
  ACCESS_MASK DesiredAccess; 
  NTSTATUS result; 
  void *KeyHandle; 
  struct _OBJECT_ATTRIBUTES ObjectAttributes; 

  ObjectAttributes.RootDirectory = 0i64;
  ObjectAttributes.Length = 48;
  ObjectAttributes.Attributes = 0x240;
  ObjectAttributes.ObjectName = HvGlobalState->punicode_string8;
  *&ObjectAttributes.SecurityDescriptor = 0i64;
  DesiredAccess = SpecificAccess != 0 ? 0xF003F : 0x20019;
  if ( IsValueExists )
  {
    result = ZwCreateKey(&KeyHandle, DesiredAccess, &ObjectAttributes, 0, 0i64, 0, Disposition);
    if ( result < 0 )
      return result;
  }
  else
  {
    result = ZwOpenKey(&KeyHandle, DesiredAccess, &ObjectAttributes);
    if ( result < 0 )
      return result;
    if ( Disposition )
      *Disposition = 2;
  }
  *Data = KeyHandle;
  return result;
}