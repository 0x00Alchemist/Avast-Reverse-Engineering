__int64 __fastcall Hypervisor::HvEntry(PDRIVER_OBJECT DriverObject, UNICODE_STRING *RegistryPath)
{
  int append; 
  ULONG ActiveProcessorCount;
  __int64 Length; 
  __int64 v8; 
  PUNICODE_STRING v9; 
  int StandardCpuInfo; 
  __int64 v11; 
  struct_HvGlobalState *v12; 
  __int64 ProcessorType; 
  __int64 HypervisorInfo; 
  __int128 v15; 
  __int128 v16;
  const wchar_t *v17; 
  const wchar_t *v18; 
  __int128 v19; 
  int dword158; 
  int dword1338; 
  char v22; 
  bool v23; 
  char v24; 
  char byte502;
  _QWORD *p_qword4B8; 
  unsigned __int64 v27; 
  struct_HvGlobalState *v28; 
  __int64 (__fastcall *pfuncED0)(__int64 (__fastcall *)(), _QWORD); 
  struct_HvGlobalState *v30; 
  unsigned int v31;
  char *v32;
  char *v33; 
  __int64 v34;
  ULONG v35;
  int CurrentProcessorNumber; 
  _QWORD *p_qwordD40; 
  _QWORD *p_qwordD68; 
  _QWORD *p_qwordE20; 
  __int64 v40;
  PVOID hPwrStateCallback;
  bool v42; 
  __int128 v43; 
  struct _PROCESSOR_NUMBER ProcNumber[2]; 
  PFILE_OBJECT FileObject; 
  PDEVICE_OBJECT DeviceObj; 
  ULONG Seed[2]; 
  PDEVICE_OBJECT DeviceObject;
  __int64 (*v49)(); 
  __int64 v50[2]; 
  struct _UNICODE_STRING DestinationString; 
  struct _UNICODE_STRING SystemRoutineName; 
  struct _UNICODE_STRING PowerStateCallbackStr; 
  struct _UNICODE_STRING SymbolicLinkName; 
  struct _GROUP_AFFINITY Affinity; 
  struct _GROUP_AFFINITY PreviousAffinity; 
  struct _OSVERSIONINFOW VersionInformation; 
  struct _OBJECT_ATTRIBUTES ObjectName; 

  if ( InitSafeBootMode )
  {
    append = 0xC000035F;
    goto LABEL_3;
  }
  append = Hypervisor::HvGetProductType(DriverObject, RegistryPath);
  if ( append < 0 )
    goto LABEL_3;
  Hypervisor::KlibCallbackWorker();
  gDriverObject = DriverObject;
  DriverObject->MajorFunction[0] = sub_140008748;
  DriverObject->DriverUnload = 0i64;
  DriverObject->MajorFunction[2] = sub_140008748;
  DriverObject->MajorFunction[14] = sub_1400087BC;
  DriverObject->MajorFunction[16] = sub_14000AB30;
  ActiveProcessorCount = KeQueryActiveProcessorCountEx(0xFFFFu);
  RtlInitUnicodeString(&DestinationString, aswVmmDeviceStr[HvProductType]);
  append = Util::IoCreateDeviceSecureWrapper(
             gDriverObject,
             8 * ActiveProcessorCount + 0x1458,
             &DestinationString,
             0x22u,
             0x100,
             0,
             L"np",
             0i64,
             &DeviceObj);
  if ( append )
    goto LABEL_125;
  HvGlobalState = DeviceObj->DeviceExtension;
  Util::MmQuery(RegistryPath, &HvGlobalState->dword134);
  HvGlobalState->qword0 = DeviceObj;
  HvGlobalState->osversioninfow18.dwOSVersionInfoSize = 0x11C;
  RtlGetVersion(&HvGlobalState->osversioninfow18);
  if ( Util::CheckDdiAvailability(0x6020000u) )
    HvGlobalState->byte15D = 1;
  else
    HvGlobalState->byte15C = Util::CheckDdiAvailability(0x6010000u);
  if ( Util::CheckDdiAvailability(0xA000000u) )
  {
    HvGlobalState->byte15E = 1;
    HvGlobalState->byte15F = NtBuildNumber >= 0x36B0u;
    HvGlobalState->byte160 = NtBuildNumber >= 0x4268u;
    HvGlobalState->byte161 = NtBuildNumber >= 0x55F0u;
  }
  HvGlobalState->dword4A8 = ActiveProcessorCount + 16;
  HvGlobalState->byte4F2 = 0;
  HvGlobalState->byte4F4 = append + 1;
  HvGlobalState->byte4F3 = append + 1;
  HvGlobalState->qword508 = 50000i64;
  HvGlobalState->word52A = 0x585F;
  HvGlobalState->word52C = 0x585F;
  HvGlobalState->word52E = 0x585F;
  *Seed = KeQueryPerformanceCounter(0i64);
  HvGlobalState->dword530 = RtlRandomEx(Seed);
  IoInitializeRemoveLockEx(&HvGlobalState->io_remove_lock488, 0x4D4D5641u, 0, 0, 0x20u);
  append = IoAcquireRemoveLockEx(&HvGlobalState->io_remove_lock488, 0x4D4D5641, &File, 1u, 0x20u);
  if ( append < 0 )
    goto LABEL_3;
  dword_140045680 |= 1u;
  append = ExInitializeResourceLite(&HvGlobalState->eresource188);
  if ( append < 0 )
    goto LABEL_3;
  Length = RegistryPath->Length;
  dword_140045680 |= 0x20u;
  v8 = Length + 24;
  HvGlobalState->punicode_string8 = ExAllocatePoolWithTag(PagedPool, v8 + 16, 0x4D4D5641u);
  v9 = HvGlobalState->punicode_string8;
  if ( !v9 )
    goto LABEL_15;
  dword_140045680 |= 0x400u;
  v9->Length = 0;
  HvGlobalState->punicode_string8->MaximumLength = v8;
  HvGlobalState->punicode_string8->Buffer = &HvGlobalState->punicode_string8[1].Length;
  RtlCopyUnicodeString(HvGlobalState->punicode_string8, RegistryPath);
  append = RtlAppendUnicodeToString(HvGlobalState->punicode_string8, L"\\Parameters");
  if ( append < 0 )
    goto LABEL_3;
  HvGlobalState->byte150 = Utill::GetExtendedCpuInfo() != 0;
  StandardCpuInfo = Util::GetStandardCpuInfo();
  HvGlobalState->dword158 = StandardCpuInfo;
  v12 = HvGlobalState;
  HvGlobalState->dword154 = StandardCpuInfo;
  if ( !HvGlobalState->dword158 )
  {
    append = 0xC00000BB;
    goto LABEL_3;
  }
  if ( sub_140024FC0(v12, v11) )
    HvGlobalState->byte150 = 0;
  if ( HvGlobalState->dword158 == 3 )
    HvGlobalState->dword158 = 1;
  sub_14002370C(1);
  ProcessorType = __cpuid(1, 0);
  DWORD1(v43) = EBX(ProcessorType);             // Brand ID
  if ( ECX(ProcessorType) < 0 )
  {
    HypervisorInfo = __cpuid(0x40000000, 0);
    HvGlobalState->dword4EC = EAX(HypervisorInfo);
    *&HvGlobalState->HypervisorVendor = EBX(HypervisorInfo);
    HvGlobalState->dword4E4 = ECX(HypervisorInfo);
    HvGlobalState->dword4E8 = EDX(HypervisorInfo);
    HvGlobalState->byte4F0 = 1;
    if ( !HvGlobalState->byte501
      || RtlCompareMemory(&HvGlobalState->HypervisorVendor, "KVMKVMKVM", 0xCui64) == 12
      || RtlCompareMemory(&HvGlobalState->HypervisorVendor, "Microsoft Hv", 0xCui64) == 12
      || RtlCompareMemory(&HvGlobalState->HypervisorVendor, "VBoxVBoxVBox", 0xCui64) == 12 )
    {
      HvGlobalState->byte150 = 0;
    }
  }
  if ( HvGlobalState->byte150 )
  {
    memset(&ObjectName, 0, sizeof(ObjectName));
    if ( HvProductType )
    {
      if ( HvProductType != 1 )
      {
        if ( HvProductType != 2 )
        {
          if ( HvProductType != 3 )
          {
LABEL_41:
            if ( IoGetDeviceObjectPointer(&ObjectName, 1u, &FileObject, &DeviceObject) >= 0
              || IoGetDeviceObjectPointer(&ObjectName.ObjectName, 1u, &FileObject, &DeviceObject) >= 0
              || IoGetDeviceObjectPointer(&ObjectName.SecurityDescriptor, 1u, &FileObject, &DeviceObject) >= 0 )
            {
              ObfDereferenceObject(FileObject);
              HvGlobalState->byte150 = 0;
            }
            goto LABEL_45;
          }
          LODWORD(v43) = 0x1E001C;
          *(&v43 + 1) = L"\\Device\\AswVmm";
          v15 = v43;
          *(&v43 + 1) = L"\\Device\\AvgVmm";
          LODWORD(v43) = 0x1E001C;
          *&ObjectName.Length = v15;
          v16 = v43;
          *(&v43 + 1) = L"\\Device\\NllVmm";
LABEL_40:
          *&ObjectName.ObjectName = v16;
          LODWORD(v43) = 0x1E001C;
          *&ObjectName.SecurityDescriptor = v43;
          goto LABEL_41;
        }
        *(&v43 + 1) = L"\\Device\\AswVmm";
        v17 = L"\\Device\\AvgVmm";
LABEL_39:
        LODWORD(v43) = 1966108;
        v19 = v43;
        *(&v43 + 1) = v17;
        LODWORD(v43) = 1966108;
        *&ObjectName.Length = v19;
        v16 = v43;
        *(&v43 + 1) = L"\\Device\\AvrVmm";
        goto LABEL_40;
      }
      v18 = L"\\Device\\AswVmm";
    }
    else
    {
      v18 = L"\\Device\\AvgVmm";
    }
    *(&v43 + 1) = v18;
    v17 = L"\\Device\\NllVmm";
    goto LABEL_39;
  }
LABEL_45:
  if ( HvGlobalState->byte15D && (HvGlobalState->dword134 & 0x2000000) != 0 )
    HvGlobalState->byte150 = 0;
  if ( !HvGlobalState->byte150 )
  {
    VersionInformation.dwOSVersionInfoSize = 276;
    if ( RtlGetVersion(&VersionInformation) >= 0
      && (VersionInformation.dwMajorVersion > 6
       || VersionInformation.dwMajorVersion == 6 && VersionInformation.dwMinorVersion >= 2) )
    {
      NonPagedPool_0 = 512;                     // NonPagedPoolNx
      dword_140045668 = 0x40000000;
    }
  }
  if ( HvGlobalState->byte15E || HvGlobalState->byte150 )
  {
    append = sub_140021D50();
    if ( append < 0 )
      goto LABEL_3;
  }
  if ( HvGlobalState->byte150 )
  {
    sub_1400221C8();
    dword158 = HvGlobalState->dword158;
    if ( dword158 != 1 )
    {
      if ( dword158 != 2 )
        goto LABEL_66;
      goto LABEL_65;
    }
    dword1338 = HvGlobalState->dword1338;
    if ( ((dword1338 & 0x8000) != 0 || HvGlobalState->dwordEB0 == 6 && HvGlobalState->dwordEB4 >= 0x3Au)
      && (dword1338 & 1) != 0 )
    {
LABEL_65:
      HvGlobalState->byte4F1 = 1;
      *&HvGlobalState->byte4F2 = 1;
    }
  }
LABEL_66:
  HvGlobalState->dword170 = ActiveProcessorCount;
  if ( sub_14002804E() )
  {
    v22 = ECX(__cpuid(1, 0));
    if ( ActiveProcessorCount < 2 || (v23 = (v22 & 8) == 0, v24 = 1, v23) )
      v24 = 0;
    HvGlobalState->byte162 = v24;
  }
  Util::FindSpecificHvFuncs();
  dword_140045680 |= 0x40000u;
  HvGlobalState->qword168 = *&KUSER_SHARED_DATA.InterruptTime.LowPart;
  byte502 = HvGlobalState->byte502;
  p_qword4B8 = &HvGlobalState->qword4B8;
  HvGlobalState->qword4C0 = &HvGlobalState->qword4B8;
  *p_qword4B8 = p_qword4B8;
  Util::HvIntegrityCheck(DriverObject->DriverStart, DriverObject->DriverSize);
  if ( !HvGlobalState->byte150 )
    goto LABEL_111;
  v23 = (dword_140045680 & 0x200) == 0;
  HvGlobalState->qword178 = 0i64;
  if ( v23 )
  {
    v27 = ((0x29F8 * ActiveProcessorCount + 0xFFFF) & 0xFFFF0000) + 0xC0000;
    if ( !byte502 )
      v27 = ((0x29F8 * ActiveProcessorCount + 0xFFFF) & 0xFFFF0000) + 0x80000;
    append = sub_140022904(v27);
    if ( append < 0 )
      goto LABEL_3;
    dword_140045680 |= 0x200u;
  }
  if ( !HvGlobalState->byte502 || (append = sub_14001C6A0(), append >= 0) )
  {
    if ( HvGlobalState->byte503 )
    {
      v49 = sub_140020F80;
      if ( (HalDispatchTable->HalSetSystemInformation)(1i64, 8i64, &v49) >= 0 )
        dword_140045680 |= 0x10000u;
      else
        HvGlobalState->byte503 = 0;
    }
    v28 = HvGlobalState;
    if ( HvGlobalState->byte504 )
    {
      pfuncED0 = HvGlobalState->pfuncED0;
      if ( pfuncED0
        && HvGlobalState->qwordED8
        && (HvGlobalState->qword430 = pfuncED0(sub_140020F98, 0i64), v28 = HvGlobalState, HvGlobalState->qword430) )
      {
        dword_140045680 |= 0x20000u;
      }
      else
      {
        v28->byte504 = 0;
      }
    }
    HvGlobalState->qword428 = KeRegisterProcessorChangeCallback(CallbackFunction, 0i64, 0);
    if ( HvGlobalState->qword428 )
      dword_140045680 |= 0x80u;
    dword_140045680 |= 0x10u;
    HvGlobalState->qword470 = 0xFFFFFFFFFFFFFFFFui64 << EAX(__cpuid(0x80000008, 0));
    sub_140022D18();
    append = Hypervisor::HvAllocatePhysMemory();
    if ( append >= 0 )
    {
      v30 = HvGlobalState;
      v31 = 0;
      if ( HvGlobalState->dword170 )
      {
        while ( 1 )
        {
          v32 = sub_140022A14(0x29F8i64);
          v33 = v32;
          if ( !v32 )
            break;
          sub_1400296C0(v32, 0, 0x29F8ui64);
          v34 = v31++;
          *&HvGlobalState[1].osversioninfow18.szCSDVersion[4 * v34 + 56] = v33;
          v30 = HvGlobalState;
          if ( v31 >= HvGlobalState->dword170 )
            goto LABEL_95;
        }
LABEL_15:
        append = 0xC0000017;
        goto LABEL_3;
      }
LABEL_95:
      v35 = 0;
      if ( v30->dword170 )
      {
        while ( 1 )
        {
          append = KeGetProcessorNumberFromIndex(v35, ProcNumber);
          if ( append < 0 )
            break;
          Affinity.Mask = 1i64 << ProcNumber[0].Number;
          Affinity.Group = ProcNumber[0].Group;
          *Affinity.Reserved = 0;
          Affinity.Reserved[2] = 0;
          KeSetSystemGroupAffinityThread(&Affinity, 0i64);
          CurrentProcessorNumber = KeGetCurrentProcessorNumberEx(0i64);
          if ( CurrentProcessorNumber != v35 )
          {
            append = -1073741198;
            break;
          }
          append = sub_140021E8C(
                     *&HvGlobalState[1].osversioninfow18.szCSDVersion[4 * CurrentProcessorNumber + 56],
                     CurrentProcessorNumber,
                     &Affinity);
          if ( append >= 0 && ++v35 < HvGlobalState->dword170 )
            continue;
          break;
        }
      }
      PreviousAffinity = 0i64;
      KeRevertToUserGroupAffinityThread(&PreviousAffinity);
      if ( append < 0 )
        goto LABEL_3;
      if ( sub_140022328() < 0 )
      {
        HvGlobalState->byte4C9 = 0;
      }
      else
      {
        dword_140045680 |= 0x100u;
        HvGlobalState->byte4C8 = 1;
      }
      KeInitializeEvent(&HvGlobalState->kevent408, NotificationEvent, 0);
      KeInitializeEvent(&HvGlobalState->kevent440, NotificationEvent, 0);
      KeInitializeEvent(&HvGlobalState->kevent458, NotificationEvent, 1u);
      dword_140045680 |= 0x4000u;
      HvGlobalState->qwordD38 = 0i64;
      p_qwordD40 = &HvGlobalState->qwordD40;
      HvGlobalState->qwordD48 = &HvGlobalState->qwordD40;
      *p_qwordD40 = p_qwordD40;
      HvGlobalState->qwordD60 = 0i64;
      p_qwordD68 = &HvGlobalState->qwordD68;
      HvGlobalState->qwordD70 = &HvGlobalState->qwordD68;
      *p_qwordD68 = p_qwordD68;
      HvGlobalState->qwordD78 = 0i64;
      p_qwordE20 = &HvGlobalState->qwordE20;
      HvGlobalState->qwordE28 = &HvGlobalState->qwordE20;
      *p_qwordE20 = p_qwordE20;
      if ( HvGlobalState->byte15C )
      {
        RtlInitUnicodeString(&SystemRoutineName, L"HalRequestSoftwareInterrupt");
        v50[1] = 161i64;
        v50[0] = MmGetSystemRoutineAddress(&SystemRoutineName);
        if ( v50[0] )
        {
          if ( sub_14001F5D8(v50, v40, &HvGlobalState->qwordD50) >= 0 && *HvGlobalState->qwordD50 )
            HvGlobalState->qwordD50 = 0i64;
        }
      }
LABEL_111:
      append = IoRegisterShutdownNotification(DeviceObj);
      if ( !append )
      {
        dword_140045680 |= 2u;
        *&ProcNumber[0].Group = 0i64;
        hPwrStateCallback = 0i64;
        RtlInitUnicodeString(&PowerStateCallbackStr, L"\\Callback\\PowerState");
        ObjectName.Length = 48;
        ObjectName.ObjectName = &PowerStateCallbackStr;
        ObjectName.RootDirectory = 0i64;
        ObjectName.Attributes = 64;
        *&ObjectName.SecurityDescriptor = 0i64;
        if ( ExCreateCallback(ProcNumber, &ObjectName, 0, 1u) >= 0 )
          hPwrStateCallback = ExRegisterCallback(*&ProcNumber[0].Group, sub_140020AE8, 0i64);
        if ( *&ProcNumber[0].Group )
          ObfDereferenceObject(*&ProcNumber[0].Group);
        HvGlobalState->qword420 = hPwrStateCallback;
        if ( !HvGlobalState->qword420 )
        {
          append = 0xC000000D;
          goto LABEL_3;
        }
        dword_140045680 |= 4u;
        RtlInitUnicodeString(&SymbolicLinkName, off_14002B9B0[HvProductType]);
        append = IoCreateSymbolicLink(&SymbolicLinkName, &DestinationString);
        if ( !append )
        {
          dword_140045680 |= 8u;
          if ( HvGlobalState->byte4CB )
          {
            *Seed = 0xFFFFFFFFFF676980ui64;
            KeInitializeTimerEx(&HvGlobalState->ktimerE30, SynchronizationTimer);
            KeInitializeDpc(&HvGlobalState->kdpcE70, DeferredRoutine, 0i64);
            KeSetTimerEx(&HvGlobalState->ktimerE30, *Seed, 1000, &HvGlobalState->kdpcE70);
            dword_140045680 |= 0x2000u;
          }
          HvGlobalState->kbugcheck_reason_callback_recordF00.State = 0;
          if ( KeRegisterBugCheckReasonCallback(
                 &HvGlobalState->kbugcheck_reason_callback_recordF00,
                 CallbackRoutine,
                 KbCallbackAddPages,
                 "aswVmm") )
          {
            dword_140045680 |= 0x8000u;
          }
          if ( !HvGlobalState->byte528 )
            return 0;
          append = sub_140009260(1);
          v42 = append < 0;
LABEL_126:
          if ( v42 )
            goto LABEL_3;
          return 0;
        }
      }
LABEL_125:
      v42 = append < 0;
      goto LABEL_126;
    }
  }
LABEL_3:
  (Hypervisor::HvUnload)();
  return append;
}