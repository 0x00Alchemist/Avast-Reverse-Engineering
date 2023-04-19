__int64 __fastcall Hypervisor::HvGetProductType(PDRIVER_OBJECT DriverObject, _UNICODE_STRING *RegistryPath)
{
  unsigned int Status; 
  unsigned __int16 v4; 
  unsigned __int16 i; 
  PWSTR Buffer; 
  PVOID DriverStart; 
  PCWSTR SourceString; 
  UNICODE_STRING v10; 
  UNICODE_STRING String1; 
  struct _UNICODE_STRING DestinationString; 

  Status = 0;
  if ( !RegistryPath )
    return 0xC000000D;
  HvProductType = 4;
  v4 = RegistryPath->Length >> 1;
  i = v4;
  if ( v4 )
  {
    Buffer = RegistryPath->Buffer;
    while ( Buffer[i - 1] != 92 )
    {
      if ( !--i )
        return 0xC00000EF;
    }
    if ( i + 3 <= v4 )
    {
      *&String1.Length = 0x60006;
      String1.Buffer = &Buffer[i];
      if ( RtlEqualUnicodeString(&String1, &AswString, 1u) )
      {
LABEL_9:
        HvProductType = 0;
        return Status;
      }
      if ( RtlEqualUnicodeString(&String1, &AvgString, 1u) )
      {
LABEL_11:
        HvProductType = 1;
        return Status;
      }
      if ( RtlEqualUnicodeString(&String1, &NllString, 1u) )
      {
LABEL_13:
        HvProductType = 2;
        return Status;
      }
      if ( RtlEqualUnicodeString(&String1, &AvrString, 1u) )
      {
LABEL_15:
        HvProductType = 3;
        return Status;
      }
      if ( DriverObject )
      {
        DriverStart = DriverObject->DriverStart;
        SourceString = 0i64;
        if ( sub_140025304(DriverStart, &SourceString) >= 0 )
        {
          RtlInitUnicodeString(&DestinationString, SourceString);
          RtlInitUnicodeString(&v10, L"avast");
          if ( RtlPrefixUnicodeString(&v10, &DestinationString, 1u) )
            goto LABEL_9;
          RtlInitUnicodeString(&v10, L"avg");
          if ( RtlPrefixUnicodeString(&v10, &DestinationString, 1u) )
            goto LABEL_11;
          RtlInitUnicodeString(&v10, L"avira");
          if ( RtlPrefixUnicodeString(&v10, &DestinationString, 1u) )
            goto LABEL_15;
          RtlInitUnicodeString(&v10, L"norton");
          if ( RtlPrefixUnicodeString(&v10, &DestinationString, 1u) )
            goto LABEL_13;
          RtlInitUnicodeString(&v10, L"piriform");
          if ( !RtlPrefixUnicodeString(&v10, &DestinationString, 1u) )
          {
            RtlInitUnicodeString(&v10, L"privax");
            RtlPrefixUnicodeString(&v10, &DestinationString, 1u);
          }
        }
      }
      return 0xC00000BB;
    }
  }
  return 0xC00000EF;
}

__int64 __fastcall Hypervisor::CheckProductType(_QWORD *pointerToQword, char charParameter)
{
  const char *stringPointer;
  __int64 result;

  if ( charParameter )
  {
    stringPointer = "Microsoft Hv";
  }
  else if ( HvProductType )
  {
    switch ( HvProductType )
    {
      case 1:
        stringPointer = "AVGVMMonitor";
        break;
      case 2:
        stringPointer = "NLLVMMonitor";
        break;
      case 3:
        stringPointer = "AVRVMMonitor";
        break;
      default:
        stringPointer = "INVVMMonitor";
        break;
    }
  }
  else
  {
    stringPointer = "Avast!aswVmm";
  }
  pointerToQword[3] = *stringPointer;
  pointerToQword[1] = *(stringPointer + 1);
  result = *(stringPointer + 2);
  pointerToQword[2] = result;
  return result;
}

__int64 Hypervisor::KlibCallbackWorker()
{
  unsigned int v0; 
  NTSTATUS Status; 
  void *v2; 
  const WCHAR *wPath; 
  NTSTATUS CallbackStatus; 
  unsigned int EntryContext; 
  struct _OBJECT_ATTRIBUTES ObjectAttributes; 
  struct _RTL_QUERY_REGISTRY_TABLE QueryTable; 
  __int64 v9; 
  int v10; 
  __int128 v11; 
  __int128 v12; 
  __int64 v13; 
  struct _UNICODE_STRING Path; 
  const wchar_t *v15; 
  const wchar_t *v16; 

  v0 = HvProductType;
  *&Path.Length = L"aswSP";
  Path.Buffer = L"avgSP";
  v15 = L"nllSP";
  v16 = L"avrSP";
  if ( byte_140045690 )
  {
    Status = 0xE0800005;
    goto LABEL_16;
  }
  if ( HvProductType >= 4 )
  {
    Status = 0xC0000058;
    goto LABEL_16;
  }
  v2 = HvProductType;
  wPath = *(&Path.Length + HvProductType);
  QueryTable.QueryRoutine = 0i64;
  QueryTable.Flags = 292;
  QueryTable.Name = L"Start";
  QueryTable.EntryContext = &EntryContext;
  QueryTable.DefaultType = 0x4000000;
  QueryTable.DefaultData = 0i64;
  QueryTable.DefaultLength = 0;
  v9 = 0i64;
  v10 = 0;
  v11 = 0i64;
  v12 = 0i64;
  v13 = 0i64;
  if ( RtlQueryRegistryValues(1u, wPath, &QueryTable, 0i64, 0i64) >= 0 && EntryContext <= 2 )
    IsQueriedRegistryValues = 1;
  if ( IsQueriedRegistryValues )
  {
    CallbackStatus = Util::CreateKlibCallback(v0);
    Status = CallbackStatus;
    if ( CallbackStatus == 0xC0000034 )         // Not found
    {
      RtlInitUnicodeString(&Path, aswKlibInitCallbackStr[v2]);
      ObjectAttributes.Length = 48;
      ObjectAttributes.RootDirectory = 0i64;
      ObjectAttributes.Attributes = 0x50;
      ObjectAttributes.ObjectName = &Path;
      *&ObjectAttributes.SecurityDescriptor = 0i64;
      Status = ExCreateCallback(&CallbackObject, &ObjectAttributes, 1u, 1u);
      if ( Status < 0 )
        goto LABEL_16;
      CallbackRegistration = ExRegisterCallback(CallbackObject, Util::RegisterKlibCallback, v2);
      if ( !CallbackRegistration )
        qword_140045700 = 0i64;
    }
    else if ( CallbackStatus )
    {
      goto LABEL_16;
    }
  }
  Status = sub_1400261B0();
  if ( Status >= 0 )
  {
    qword_140045688 = Util::UnregisterCallback;
    byte_140045690 = 1;
  }
LABEL_16:
  if ( Status < 0 )
    Util::UnregisterCallback();
  return Status;
}

__int64 Hypervisor::HvAllocatePhysMemory()
{
  NTSTATUS Status; 
  PPHYSICAL_MEMORY_RANGE PhysicalMemoryRanges; 
  char *Memory; 
  LARGE_INTEGER NumberOfBytes; 
  char *PhysMemRange; 
  LONGLONG v5; 
  SIZE_T FinalSize; 
  _OWORD *Allocated; 

  Status = 0;
  PhysicalMemoryRanges = MmGetPhysicalMemoryRanges();
  Memory = PhysicalMemoryRanges;
  if ( PhysicalMemoryRanges )
  {
    NumberOfBytes = PhysicalMemoryRanges->NumberOfBytes;
    PhysMemRange = PhysicalMemoryRanges;
    while ( NumberOfBytes.QuadPart )
    {
      v5 = NumberOfBytes.QuadPart + *PhysMemRange;
      if ( v5 > *HvGlobalState->gap478 )
        *HvGlobalState->gap478 = v5;
      NumberOfBytes = *(PhysMemRange + 24);
      PhysMemRange += 16;
    }
    if ( *HvGlobalState->gap478 < 0x100000000i64 )
      *HvGlobalState->gap478 = 0x100000000i64;
    FinalSize = PhysMemRange - Memory + 16;
    *&HvGlobalState->gap478[8] = ExAllocatePoolWithTag(NonPagedPool_0, FinalSize, 'MMVA');
    Allocated = *&HvGlobalState->gap478[8];
    if ( Allocated )
      sub_140029400(Allocated, Memory, FinalSize);
    else
      Status = 0xC0000017;
    ExFreePoolWithTag(Memory, 0);
  }
  else
  {
    return 0xC0000001;
  }
  return Status;
}

__int64 Hypervisor::HvCreateImageInfoNotifyRoutine()
{
  NTSTATUS ImageNotifyRoutine; 
  
  ImageNotifyRoutine = 0;
  KeEnterCriticalRegion();
  ExAcquireResourceExclusiveLite(&HvGlobalState->eresource188, 1u);
  if ( (dword_140045680 & 0x40) == 0 )
  {
    ImageNotifyRoutine = PsSetLoadImageNotifyRoutine(Notify::GetSpecificImageInfo);
    if ( ImageNotifyRoutine >= 0 )
    {
      IoAcquireRemoveLockEx(&HvGlobalState->io_remove_lock488, Notify::GetSpecificImageInfo, &File, 1u, 0x20u);
      dword_140045680 |= 0x40u;
    }
  }
  ExReleaseResourceLite(&HvGlobalState->eresource188);
  KeLeaveCriticalRegion();
  return ImageNotifyRoutine;
}

__int64 __fastcall Hypervisor::HvCreateClose(PDRIVER_OBJECT DriverObject, IRP *pIRP)
{
  IoAcquireRemoveLockEx(&HvGlobalState->io_remove_lock488, pIRP, &File, 1u, 0x20u);
  pIRP->IoStatus.Status = 0;
  pIRP->IoStatus.Information = 0i64;
  IofCompleteRequest(pIRP, 0);
  IoReleaseRemoveLockEx(&HvGlobalState->io_remove_lock488, pIRP, 0x20u);
  return 0i64;
}

__int64 __fastcall sub_14000AB30(PDRIVER_OBJECT DriverObject, IRP *pIRP)
{
  ULONG v4; 
  _BYTE Data[12];

  *&Data[8] = 0;
  v4 = 0;
  *Data = NtBuildNumber;
  IoAcquireRemoveLockEx(&HvGlobalState->io_remove_lock488, pIRP, &File, 1u, 0x20u);
  if ( *&KUSER_SHARED_DATA.InterruptTime.LowPart - HvGlobalState->qword168 >= 0x430E23400ui64 )
  {
    if ( Util::RegistryCheck(&Data[4], 1, 0, &v4) >= 0 )
      ZwSetValueKey(*&Data[4], &LastNtBuildStr, 0, 4u, Data, 4u);
    if ( *&Data[4] )
      ZwClose(*&Data[4]);
  }
  if ( pIRP )
  {
    pIRP->IoStatus.Information = 0i64;
    pIRP->IoStatus.Status = 0;
    IofCompleteRequest(pIRP, 0);
  }
  IoReleaseRemoveLockEx(&HvGlobalState->io_remove_lock488, pIRP, 0x20u);
  return 0i64;
}

__int64 __fastcall Hypervisor::HvConfigRoutine(char CheckConfig)
{
  NTSTATUS Status;
  int v2; 
  void *v3; 
  __int64 v4; 
  __int64 v5; 
  PVOID Pointer; 
  PVOID hKey; 
  PVOID v8; 
  void *v9; 
  void *v10; 
  void *v11; 
  PVOID v12; 
  PVOID v13; 
  PVOID v14; 
  PVOID v15; 
  PVOID v16; 
  PVOID v17; 
  PVOID v18; 
  PVOID v19; 
  PVOID v20; 
  bool v21; 
  PVOID v22; 
  PVOID v23; 
  PVOID v24; 
  PVOID v25; 
  PVOID v26; 
  unsigned __int16 v27; 
  int v28; 
  PVOID v29; 
  PVOID v30; 
  PVOID v31; 
  PVOID v32; 
  PVOID v33; 
  PVOID v34; 
  PVOID v35; 
  ULONG v37; 
  PVOID P; 
  struct _IO_STATUS_BLOCK IoStatusBlock; 

  Status = 0;
  P = 0i64;
  v2 = 0;
  IoStatusBlock.Pointer = 0i64;
  v37 = 0;
  if ( KeGetCurrentIrql() < 2u )
  {
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&HvGlobalState->eresource188, 1u);
    Util::RegistryCheck(&IoStatusBlock, 0, CheckConfig, &v37);
    Pointer = IoStatusBlock.Pointer;
    if ( CheckConfig )
    {
      if ( IoStatusBlock.Pointer )
      {
        if ( !*HvGlobalState->gap10 )
        {
          qword_140045728 = sub_1400236A4;
          qword_140045730 = ApcRoutine;
          hKey = IoStatusBlock.Pointer;
          *HvGlobalState->gap10 = IoStatusBlock.Pointer;
          if ( ZwNotifyChangeKey(hKey, 0i64, ApcRoutine, 1, &IoStatusBlock, 4u, 1u, 0i64, 0, 1u) != 0x103 )
            *HvGlobalState->gap10 = 0i64;
        }
      }
    }
    if ( Util::QueryConfigString(Pointer, &MaskVmm, &P) >= 0 )
    {
      v8 = P;
      if ( *(P + 1) == 4 )
        HvGlobalState->byte4F4 = *(P + 3) != 0;
      ExFreePoolWithTag(v8, 'MMVA');
      P = 0i64;
    }
    v9 = *HvGlobalState->gap510;
    if ( v9 )
    {
      ExFreePoolWithTag(v9, 'MMVA');
      *HvGlobalState->gap510 = 0i64;
    }
    if ( Util::QueryConfigString(Pointer, &OtherVmms, &P) >= 0 )
    {
      if ( *(P + 1) == 7 )
        *HvGlobalState->gap510 = P;
      else
        ExFreePoolWithTag(P, 'MMVA');
      P = 0i64;
    }
    v10 = *&HvGlobalState->gap510[16];
    if ( v10 )
    {
      ExFreePoolWithTag(v10, 'MMVA');
      *&HvGlobalState->gap510[16] = 0i64;
    }
    if ( Util::QueryConfigString(Pointer, DontHideVmmFiles, &P) >= 0 )
    {
      if ( *(P + 1) == 7 )
        *&HvGlobalState->gap510[16] = P;
      else
        ExFreePoolWithTag(P, 'MMVA');
      P = 0i64;
    }
    v11 = *&HvGlobalState->gap510[8];
    if ( v11 )
    {
      ExFreePoolWithTag(v11, 'MMVA');
      *&HvGlobalState->gap510[8] = 0i64;
    }
    if ( Util::QueryConfigString(Pointer, DontHideVmmPaths, &P) >= 0 )
    {
      if ( *(P + 1) == 7 )
        *&HvGlobalState->gap510[8] = P;
      else
        ExFreePoolWithTag(P, 'MMVA');
      P = 0i64;
    }
    if ( Util::QueryConfigString(Pointer, DontDetectOtherVmms, &P) >= 0 )
    {
      v12 = P;
      if ( *(P + 1) == 4 )
        HvGlobalState->gap4F5[11] = *(P + 3) != 0;
      ExFreePoolWithTag(v12, 'MMVA');
      P = 0i64;
    }
    if ( Util::QueryConfigString(Pointer, VirtualizeUnderOtherVmm, &P) >= 0 )
    {
      v13 = P;
      if ( *(P + 1) == 4 )
        HvGlobalState->byte501 = *(P + 3) != 0;
      ExFreePoolWithTag(v13, 'MMVA');
      P = 0i64;
    }
    if ( Util::QueryConfigString(Pointer, &TimingTreshold, &P) >= 0 )
    {
      v14 = P;
      if ( *(P + 1) == 4 )
        HvGlobalState->qword508 = *(P + 3);
      ExFreePoolWithTag(v14, 'MMVA');
      P = 0i64;
    }
    if ( Util::QueryConfigString(Pointer, &AutoStart, &P) >= 0 )
    {
      v15 = P;
      if ( *(P + 1) == 4 )
        HvGlobalState->byte528 = *(P + 3) != 0;
      ExFreePoolWithTag(v15, 'MMVA');
      P = 0i64;
    }
    if ( Util::QueryConfigString(Pointer, &Interrupts, &P) >= 0 )
    {
      v16 = P;
      if ( *(P + 1) == 4 )
        *(&HvGlobalState->byte528 + 1) = *(P + 3) != 0;
      ExFreePoolWithTag(v16, 'MMVA');
      P = 0i64;
    }
    if ( Util::QueryConfigString(Pointer, &ProcMon, &P) < 0 )
    {
      v18 = P;
    }
    else
    {
      v17 = P;
      if ( *(P + 1) == 4 )
        HvGlobalState->byte502 = *(P + 3) != 0;
      ExFreePoolWithTag(v17, 'MMVA');
      v18 = 0i64;
      P = 0i64;
    }
    if ( CheckConfig )
    {
      if ( Util::QueryConfigString(Pointer, &PMI, &P) < 0 )
      {
        v18 = P;
      }
      else
      {
        v19 = P;
        if ( *(P + 1) == 4 )
          HvGlobalState->byte503 = *(P + 3) != 0;
        ExFreePoolWithTag(v19, 'MMVA');
        v18 = 0i64;
        P = 0i64;
      }
    }
    if ( *HvGlobalState->gap438 != 1 )
    {
      if ( HvGlobalState->byte4F4 )
      {
        if ( Util::QueryConfigString(Pointer, &NestedVmbios, &P) >= 0 )
        {
          v20 = P;
          if ( *(P + 1) == 4 )
          {
            v21 = *(P + 3) == 0;
            HvGlobalState->byte4F2 = *(P + 3) != 0;
            HvGlobalState->byte4F3 = v21;
          }
          ExFreePoolWithTag(v20, 'MMVA');
          P = 0i64;
        }
        if ( Util::QueryConfigString(Pointer, &MaskVmbios, &P) >= 0 )
        {
          v22 = P;
          if ( *(P + 1) == 4 )
            HvGlobalState->byte4F3 = *(P + 3) != 0;
          ExFreePoolWithTag(v22, 'MMVA');
          P = 0i64;
        }
      }
      if ( CheckConfig )
      {
        if ( Util::QueryConfigString(Pointer, DontDoSmth, &P) >= 0 )
        {
          if ( *(P + 1) == 4 && *(P + 3) )
            v2 = 1;
          ExFreePoolWithTag(P, 'MMVA');
          P = 0i64;
        }
        if ( Util::QueryConfigString(Pointer, &NtBuildVirt, &P) >= 0 )
        {
          v23 = P;
          if ( *(P + 1) == 4 )
            HvGlobalState->word52A = *(P + 6);
          ExFreePoolWithTag(v23, 'MMVA');
          P = 0i64;
        }
        if ( Util::QueryConfigString(Pointer, NtBuildSyscallVmm, &P) >= 0 )
        {
          v24 = P;
          if ( *(P + 1) == 4 )
            HvGlobalState->word52C = *(P + 6);
          ExFreePoolWithTag(v24, 'MMVA');
          P = 0i64;
        }
        if ( Util::QueryConfigString(Pointer, NtBuildSyscallIfh, &P) >= 0 )
        {
          v25 = P;
          if ( *(P + 1) == 4 )
            HvGlobalState->word52E = *(P + 6);
          ExFreePoolWithTag(v25, 'MMVA');
          P = 0i64;
        }
        if ( Util::QueryConfigString(Pointer, BlockSmth, &P) >= 0 )
        {
          if ( *(P + 1) == 4 && *(P + 3) )
            v2 |= 2u;
          ExFreePoolWithTag(P, 'MMVA');
          P = 0i64;
        }
        if ( Util::QueryConfigString(Pointer, &LastNtBuildStr, &P) >= 0 )
        {
          v26 = P;
          if ( *(P + 1) == 4 )
          {
            v27 = *(P + 6);
            *&HvGlobalState->gap163[1] = v27;
            if ( v27 < NtBuildNumber )
              v2 |= 4u;
          }
          ExFreePoolWithTag(v26, 'MMVA');
          P = 0i64;
        }
        v28 = v2 | 8;
        if ( NtBuildNumber < HvGlobalState->word52A )
          v28 = v2;
        if ( v28 )
        {
          *&HvGlobalState->gap4F5[3] = v28;
          HvGlobalState->gap4F5[7] = 1;
          if ( (v28 & 6) != 0 )
            HvGlobalState->gap4F5[8] = 1;
        }
        if ( !HvGlobalState->gap4F5[7] )
        {
          if ( Util::QueryConfigString(Pointer, &DontSyscallVmm, &P) >= 0 )
          {
            v29 = P;
            if ( *(P + 1) == 4 )
              HvGlobalState->gap4F5[7] = *(P + 3) != 0;
            ExFreePoolWithTag(v29, 'MMVA');
            P = 0i64;
          }
          if ( !HvGlobalState->gap4F5[7] && NtBuildNumber >= HvGlobalState->word52C )
            HvGlobalState->gap4F5[7] = 1;
        }
        if ( !HvGlobalState->gap4F5[8] )
        {
          if ( Util::QueryConfigString(Pointer, &DontSyscallIfh, &P) >= 0 )
          {
            v30 = P;
            if ( *(P + 1) == 4 )
              HvGlobalState->gap4F5[8] = *(P + 3) != 0;
            ExFreePoolWithTag(v30, 'MMVA');
            P = 0i64;
          }
          if ( !HvGlobalState->gap4F5[8] && NtBuildNumber >= HvGlobalState->word52E )
            HvGlobalState->gap4F5[8] = 1;
        }
      }
      if ( Util::QueryConfigString(Pointer, &TimingFix, &P) >= 0 )
      {
        v31 = P;
        if ( *(P + 1) == 4 )
          HvGlobalState->gap4F5[9] = *(P + 3) != 0;
        ExFreePoolWithTag(v31, 'MMVA');
        P = 0i64;
      }
      if ( Util::QueryConfigString(Pointer, &TscExiting, &P) >= 0 )
      {
        v32 = P;
        if ( *(P + 1) == 4 )
          HvGlobalState->gap4F5[10] = *(P + 3) != 0;
        ExFreePoolWithTag(v32, 'MMVA');
        P = 0i64;
      }
      if ( Util::QueryConfigString(Pointer, &NestedPaging, &P) >= 0 )
      {
        v33 = P;
        if ( *(P + 1) == 4 )
          HvGlobalState->byte4C9 = *(P + 3) != 0;
        ExFreePoolWithTag(v33, 'MMVA');
        P = 0i64;
      }
      if ( Util::QueryConfigString(Pointer, NP4KB, &P) >= 0 )
      {
        v34 = P;
        if ( *(P + 1) == 4 )
          HvGlobalState->gap4CA = *(P + 3) != 0;
        ExFreePoolWithTag(v34, 'MMVA');
        P = 0i64;
      }
      if ( Util::QueryConfigString(Pointer, &NestedUsage, &P) < 0 )
      {
        v18 = P;
      }
      else
      {
        v35 = P;
        if ( *(P + 1) == 4 )
          HvGlobalState->byte4CB = *(P + 3) != 0;
        ExFreePoolWithTag(v35, 'MMVA');
        v18 = 0i64;
      }
    }
    if ( HvGlobalState->byte4CB )
    {
      HvGlobalState->byte4C9 = 1;
      HvGlobalState->gap4CA = 1;
    }
    if ( HvGlobalState->byte15D )
      HvGlobalState->byte502 = 1;
    if ( HvGlobalState->gap4F5[9] )
      HvGlobalState->gap4F5[10] = 1;
    if ( !CheckConfig && HvGlobalState->byte4C9 && !HvGlobalState->byte4C8 )
      HvGlobalState->byte4C9 = 0;
    ExReleaseResourceLite(&HvGlobalState->eresource188);
    KeLeaveCriticalRegion();
    if ( v18 )
      ExFreePoolWithTag(v18, 'MMVA');
    if ( Pointer && *HvGlobalState->gap10 != Pointer )
      ZwClose(Pointer);
  }
  else
  {
    Status = 0xC00000BB;
    _InterlockedExchangeAdd(HvGlobalState->gapF30, 1u);
    v3 = Util::RetAddr();
    *&HvGlobalState->gapF30[16 * v4 + 8] = v3;
    *&HvGlobalState->gapF30[16 * v5 + 16] = 0xC00000BB;
  }
  return Status;
}

void __fastcall Hypervisor::BugCheckCallback(
        KBUGCHECK_CALLBACK_REASON Reason,
        struct _KBUGCHECK_REASON_CALLBACK_RECORD *Record,
        _DWORD *ReasonSpecificData,
        ULONG ReasonSpecificDataLength)
{
  unsigned __int64 v5; 
  __int64 v6; 
  __int64 v7; 
  struct_v12 *CSDVer; 
  unsigned __int64 v9; 
  __int64 v10; 

  if ( Reason == KbCallbackAddPages && ReasonSpecificDataLength == 32 )
  {
    v5 = 0i64;
    v6 = *ReasonSpecificData;
    if ( *ReasonSpecificData )
    {
      v7 = (v6 - 1);
      if ( v7 >= HvGlobalState->ActiveProcessorCount )
      {
        ReasonSpecificData[2] = 0;
LABEL_12:
        *(ReasonSpecificData + 3) = v5;
        *ReasonSpecificData = v6 + 1;
        return;
      }
      CSDVer = *&HvGlobalState[1].osversioninfow18.szCSDVersion[4 * v7 + 56];
      if ( !CSDVer )
      {
        ReasonSpecificData[2] = 0x80000000;
        goto LABEL_12;
      }
      ReasonSpecificData[2] = 0x80000001;
      *(ReasonSpecificData + 2) = CSDVer->pvoid28;
      v9 = CSDVer->pmdl30->ByteCount;
    }
    else
    {
      ReasonSpecificData[2] = 0x80000001;
      v10 = *HvGlobalState->gap138;
      if ( !v10 )
        goto LABEL_12;
      *(ReasonSpecificData + 2) = v10;
      v9 = *(*&HvGlobalState->gap138[8] + 0x28i64);
    }
    v5 = v9 >> 12;
    goto LABEL_12;
  }
}

__int64 __fastcall Hypervisor::CheckVTxSupport(bool *VTxSupported)
{
  unsigned __int64 VTx; 
  bool IsSupported; 

  VTx = __readmsr(0x3Au);                       // IA32_FEATURE_CONTROL
  IsSupported = (VTx & 1) != 0 && (VTx & 4) == 0;
  *VTxSupported = IsSupported;                  // If returns 3, 5, 7 - VTx supported
  return 0i64;
}

__int64 __fastcall Hypervisor::CheckAMDSVMSupport(bool *SVMSupported)
{
  unsigned __int64 SVM; 
  bool IsSupported; 

  SVM = __readmsr(0xC0010114);                  // MSR_VM_CR
  IsSupported = (SVM & 8) != 0 && (SVM & 0x10) != 0;
  *SVMSupported = IsSupported;
  return 0i64;
}

__int64 __fastcall Hypervisor::CheckVirtualizationFeatures(bool *IsSupported)
{
  unsigned int v1; 
  void *ret; 
  __int64 v3; 
  int v4; 
  __int64 v5; 
  int StandardCpuInfo; 
  int v7; 
  void *Ret; 
  int v10; 

  v1 = 0;
  if ( !HvGlobalState->byte150 || !IsSupported )
  {
    _InterlockedExchangeAdd(HvGlobalState->gapF30, 1u);
    ret = Util::RetAddr();
    *&HvGlobalState->gapF30[16 * v5 + 8] = ret;
LABEL_11:
    *&HvGlobalState->gapF30[16 * v3 + 16] = v4;
    return v1;
  }
  StandardCpuInfo = HvGlobalState->StandardCpuInfo;
  if ( !StandardCpuInfo )
  {
    _InterlockedExchangeAdd(HvGlobalState->gapF30, 1u);
    Ret = Util::RetAddr();
    *&HvGlobalState->gapF30[16 * v10 + 8] = Ret;
    goto LABEL_11;
  }
  v7 = StandardCpuInfo - 1;
  if ( !v7 )
    return Hypervisor::CheckVTxSupport(IsSupported);
  if ( v7 == 1 )
    return Hypervisor::CheckAMDSVMSupport(IsSupported);
  return v1;
}
