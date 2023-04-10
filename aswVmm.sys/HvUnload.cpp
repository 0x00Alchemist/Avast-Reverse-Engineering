__int64 (*__fastcall Hypervisor::HvUnload(PDRIVER_OBJECT DriverObject, UNICODE_STRING *RegistryPath))(void)
{
  void *pwrStateCallback; 
  unsigned __int64 i; 
  _QWORD *v4; 
  __int64 v5; 
  struct_HvGlobalState *HvState_1; 
  struct_HvGlobalState *v7; 
  struct _MDL *v8; 
  unsigned int k; 
  struct_v12 *CSDVer; 
  void *v11; 
  void *v12; 
  void *v13; 
  void *v14; 
  unsigned __int64 v15; 
  char *v16; 
  void *pvoid370; 
  void *pvoid380; 
  void *pvoid390; 
  void *pvoid3A0; 
  void *pvoid3B0; 
  void *pvoid3C0; 
  void *pvoid28; 
  void *pvoid100; 
  int dword0; 
  struct _MDL *Mdl; 
  struct _MDL *v27; 
  struct _MDL *v28; 
  struct _MDL *v29; 
  void *v30; 
  struct _MDL *v31; 
  struct _MDL *v32; 
  struct _MDL *v33; 
  __int64 v34; 
  void *v35; 
  void *v36; 
  void *v37; 
  __int64 (*result)(void); 
  int v39[8]; 
  PCALLBACK_OBJECT CallbackObject; 
  __int64 v41; 
  struct _UNICODE_STRING DestinationString; 
  struct _UNICODE_STRING SymbolicLinkName; 
  struct _OBJECT_ATTRIBUTES ObjectAttributes; 

  if ( (GlobalStatus & 0x10) != 0 )
    sub_140020188(1, RegistryPath, 0i64);
  if ( (GlobalStatus & 0x8000) != 0 )
    KeDeregisterBugCheckReasonCallback(&HvGlobalState->kbugcheck_reason_callback_recordF00);
  if ( (GlobalStatus & 4) != 0 )
  {
    CallbackObject = 0i64;
    pwrStateCallback = HvGlobalState->PowerStateCallback;
    if ( pwrStateCallback )
    {
      RtlInitUnicodeString(&DestinationString, L"\\Callback\\PowerState");
      ObjectAttributes.Length = 48;
      ObjectAttributes.ObjectName = &DestinationString;
      ObjectAttributes.RootDirectory = 0i64;
      ObjectAttributes.Attributes = 0x40;
      *&ObjectAttributes.SecurityDescriptor = 0i64;
      if ( ExCreateCallback(&CallbackObject, &ObjectAttributes, 0, 1u) >= 0 )
        ExUnregisterCallback(pwrStateCallback);
      DriverObject = CallbackObject;
      if ( CallbackObject )
        ObfDereferenceObject(CallbackObject);
    }
    HvGlobalState->PowerStateCallback = 0i64;
  }
  if ( (GlobalStatus & 0x80u) != 0 )
  {
    KeDeregisterProcessorChangeCallback(HvGlobalState->ProcessorChangeCallback);
    HvGlobalState->ProcessorChangeCallback = 0i64;
  }
  if ( (GlobalStatus & 0x10000) != 0 )
  {
    v41 = 0i64;
    (HalDispatchTable->HalSetSystemInformation)(1i64, 8i64, &v41);
  }
  if ( (GlobalStatus & 0x20000) != 0 )
    (HvGlobalState->qwordED8)(HvGlobalState->qword430, RegistryPath);
  if ( (GlobalStatus & 2) != 0 )
    IoUnregisterShutdownNotification(HvGlobalState->HvDevice);
  if ( (GlobalStatus & 0x40) != 0 )
  {
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&HvGlobalState->eresource188, 1u);
    if ( (GlobalStatus & 0x40) != 0 && PsRemoveLoadImageNotifyRoutine(Notify::GetSpecificImageInfo) >= 0 )
    {
      IoReleaseRemoveLockEx(&HvGlobalState->io_remove_lock488, Notify::GetSpecificImageInfo, 0x20u);
      GlobalStatus &= ~0x40u;
    }
    ExReleaseResourceLite(&HvGlobalState->eresource188);
    KeLeaveCriticalRegion();
  }
  if ( (GlobalStatus & 0x800) != 0 )
  {
    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&HvGlobalState->eresource188, 1u);
    if ( (GlobalStatus & 0x800) != 0 && PsSetCreateProcessNotifyRoutineEx(NotifyRoutine, 1u) >= 0 )
    {
      IoReleaseRemoveLockEx(&HvGlobalState->io_remove_lock488, NotifyRoutine, 0x20u);
      GlobalStatus &= ~0x800u;
    }
    ExReleaseResourceLite(&HvGlobalState->eresource188);
    KeLeaveCriticalRegion();
  }
  if ( (GlobalStatus & 0x1000) != 0 )
  {
    for ( i = 1336i64; i < 3384; i += 8i64 )
    {
      v4 = *(&HvGlobalState->HvDevice + i);
      while ( v4 )
      {
        v5 = v4;
        v4 = *v4;
        sub_140022A44(v5);
      }
    }
    sub_1400296C0(&HvGlobalState->gap534[4], 0, 0x800ui64);
  }
  if ( (GlobalStatus & 1) != 0 )
  {
    sub_14000EA8C();
    if ( (GlobalStatus & 0x2000) != 0 )
      KeCancelTimer(&HvGlobalState->ktimerE30);
    IoReleaseRemoveLockAndWaitEx(&HvGlobalState->io_remove_lock488, 'MMVA', 0x20u);
    HvState_1 = HvGlobalState;
    if ( *&HvGlobalState->gap1F0[0x58] )
    {
      *&HvGlobalState->gap1F0[0x50] = 0i64;
      *&HvState_1->gap1F0[0x58] = 0i64;
    }
    *&HvState_1->gap1F0[0x60] = 0i64;
    *&HvState_1->gap1F0[0x68] = 0i64;
    *&HvState_1->gap1F0[0x70] = 0i64;
    HvState_1->gap1F0[0x90] = 0;
    v7 = HvGlobalState;
    if ( *&HvGlobalState->gap1F0[0x10] )
    {
      *&HvGlobalState->gap1F0[8] = 0i64;
      *&v7->gap1F0[0x10] = 0i64;
    }
    *&v7->gap1F0[0x18] = 0i64;
    *&v7->gap1F0[0x20] = 0i64;
    *&v7->gap1F0[0x28] = 0i64;
    v7->gap1F0[0x48] = 0;
    Util::FreeSpecificPool(0);
    while ( 1 )
    {
      v8 = *&HvGlobalState->gap4AC[4];
      if ( !v8 )
        break;
      *&HvGlobalState->gap4AC[4] = v8->Next;
      v8->Next = 0i64;
      MmFreePagesFromMdl(v8);
      ExFreePoolWithTag(v8, 0);
    }
    DriverObject = *&HvGlobalState->gap478[8];
    if ( DriverObject )
    {
      ExFreePoolWithTag(DriverObject, 'MMVA');
      *&HvGlobalState->gap478[8] = 0i64;
    }
  }
  if ( (GlobalStatus & 0x20) != 0 )
    ExDeleteResourceLite(&HvGlobalState->eresource188);
  if ( (GlobalStatus & 0x10) != 0 )
  {
    DriverObject = HvGlobalState;
    k = 0;
    if ( HvGlobalState->ActiveProcessorCount )
    {
      while ( 1 )
      {
        CSDVer = *(&DriverObject[15].DriverSection + k);
        if ( CSDVer )
          break;
LABEL_87:
        DriverObject = HvGlobalState;
        if ( ++k >= HvGlobalState->ActiveProcessorCount )
          goto LABEL_88;
      }
      if ( LODWORD(DriverObject[1].DeviceObject) == 1 )
      {
        pvoid370 = CSDVer->pvoid370;
        if ( pvoid370 )
          MmFreeContiguousMemory(pvoid370);
        pvoid380 = CSDVer->pvoid380;
        if ( pvoid380 )
          MmFreeContiguousMemory(pvoid380);
        pvoid390 = CSDVer->pvoid390;
        if ( pvoid390 )
          MmFreeContiguousMemory(pvoid390);
        pvoid3A0 = CSDVer->pvoid3A0;
        if ( pvoid3A0 )
          MmFreeContiguousMemory(pvoid3A0);
        pvoid3B0 = CSDVer->pvoid3B0;
        if ( pvoid3B0 )
          MmFreeContiguousMemory(pvoid3B0);
        pvoid3C0 = CSDVer->pvoid3C0;
        if ( pvoid3C0 )
          MmFreeContiguousMemory(pvoid3C0);
        v16 = &CSDVer->char360;
        v15 = 0x2698i64;
      }
      else
      {
        if ( LODWORD(DriverObject[1].DeviceObject) != 2 )
          goto LABEL_79;
        v11 = *&CSDVer->char360;
        if ( v11 )
          MmFreeContiguousMemory(v11);
        v12 = CSDVer->pvoid370;
        if ( v12 )
          MmFreeContiguousMemory(v12);
        v13 = CSDVer->pvoid380;
        if ( v13 )
          MmFreeContiguousMemory(v13);
        v14 = CSDVer->pvoid390;
        if ( v14 )
          MmFreeContiguousMemory(v14);
        v15 = 0x25B8i64;
        v16 = &CSDVer->char360;
      }
      sub_1400296C0(v16, 0, v15);
LABEL_79:
      pvoid28 = CSDVer->pvoid28;
      if ( pvoid28 || CSDVer->pmdl30 )
      {
        Util::FreePages(pvoid28, CSDVer->pmdl30);
        CSDVer->pvoid28 = 0i64;
        CSDVer->pmdl30 = 0i64;
      }
      pvoid100 = CSDVer->pvoid100;
      if ( pvoid100 )
      {
        ExFreePoolWithTag(pvoid100, 'MMVA');
        CSDVer->pvoid100 = 0i64;
      }
      dword0 = CSDVer->dword0;
      CSDVer->byte112 = 0;
      if ( (dword0 & 1) != 0 )
        ExDeleteResourceLite(&CSDVer->eresource40);
      sub_140022A44(CSDVer);
      goto LABEL_87;
    }
LABEL_88:
    LOBYTE(DriverObject[3].Flags) = 0;
  }
  if ( (GlobalStatus & 0x100) != 0 )
  {
    Mdl = *&HvGlobalState->gap4CC[4];
    if ( Mdl )
    {
      MmFreePagesFromMdl(Mdl);
      ExFreePoolWithTag(*&HvGlobalState->gap4CC[4], 0);
    }
    DriverObject = HvGlobalState;
    RegistryPath = HvGlobalState->StandardCpuInfo;
    if ( !RegistryPath )
      goto LABEL_112;
    RegistryPath = (RegistryPath - 1);
    if ( RegistryPath )
    {
      if ( RegistryPath != 1 )
        goto LABEL_112;
      v27 = *&HvGlobalState[1].osversioninfow18.dwMajorVersion;
      if ( v27 )
        Util::FreePages(*&HvGlobalState[1].gap10[4], v27);
      v28 = *HvGlobalState[1].osversioninfow18.szCSDVersion;
      if ( v28 )
        Util::FreePages(*&HvGlobalState[1].osversioninfow18.dwBuildNumber, v28);
      v29 = *&HvGlobalState[1].osversioninfow18.szCSDVersion[8];
      if ( v29 )
        Util::FreePages(*&HvGlobalState[1].osversioninfow18.szCSDVersion[4], v29);
      DriverObject = HvGlobalState;
      RegistryPath = *&HvGlobalState[1].osversioninfow18.szCSDVersion[16];
      if ( !RegistryPath )
        goto LABEL_112;
      v30 = *&HvGlobalState[1].osversioninfow18.szCSDVersion[12];
    }
    else
    {
      v31 = *&HvGlobalState[1].osversioninfow18.szCSDVersion[16];
      if ( v31 )
        Util::FreePages(*&HvGlobalState[1].osversioninfow18.szCSDVersion[12], v31);
      v32 = *&HvGlobalState[1].osversioninfow18.szCSDVersion[24];
      if ( v32 )
        Util::FreePages(*&HvGlobalState[1].osversioninfow18.szCSDVersion[20], v32);
      v33 = *&HvGlobalState[1].osversioninfow18.szCSDVersion[36];
      if ( v33 )
        Util::FreePages(*&HvGlobalState[1].osversioninfow18.szCSDVersion[32], v33);
      DriverObject = HvGlobalState;
      RegistryPath = *&HvGlobalState[1].osversioninfow18.szCSDVersion[48];
      if ( !RegistryPath )
        goto LABEL_112;
      v30 = *&HvGlobalState[1].osversioninfow18.szCSDVersion[44];
    }
    Util::FreePages(v30, RegistryPath);
LABEL_112:
    HvGlobalState->byte4C8 = 0;
  }
  if ( (GlobalStatus & 0x4000) != 0 )
  {
    sub_1400224A4(&HvGlobalState->qwordD40, 'MMVV');
    sub_1400224A4(&HvGlobalState->qwordD68, 'MMVV');
    sub_1400296C0(HvGlobalState->gapD80, 0, 0xA0ui64);
    sub_1400224A4(&HvGlobalState->qwordE20, 'MMVA');
  }
  if ( (GlobalStatus & 0x40000) != 0 )
    sub_1400224A4(&HvGlobalState->qword4B8, 'MMVA');
  if ( (GlobalStatus & 0x200) != 0 )
  {
    v34 = *&HvGlobalState->gap138[16];
    if ( v34 )
    {
      if ( *(v34 + 64) != qword_140045698 )
        __debugbreak();
      *&HvGlobalState->gap138[16] = 0i64;
    }
    RegistryPath = HvGlobalState;
    DriverObject = *HvGlobalState->gap138;
    if ( DriverObject )
    {
      Util::FreePages(DriverObject, *&HvGlobalState->gap138[8]);
      *HvGlobalState->gap138 = 0i64;
      *&HvGlobalState->gap138[8] = 0i64;
    }
  }
  if ( (GlobalStatus & 0x400) != 0 )
  {
    v35 = *HvGlobalState->gap10;
    *HvGlobalState->gap10 = 0i64;
    _InterlockedOr(v39, 0);
    if ( v35 )
      ZwClose(v35);
    ExFreePoolWithTag(HvGlobalState->punicode_string8, 'MMVA');
    v36 = *HvGlobalState->gap510;
    if ( v36 )
      ExFreePoolWithTag(v36, 'MMVA');
    v37 = *&HvGlobalState->gap510[16];
    if ( v37 )
      ExFreePoolWithTag(v37, 'MMVA');
    DriverObject = *&HvGlobalState->gap510[8];
    if ( DriverObject )
      ExFreePoolWithTag(DriverObject, 'MMVA');
  }
  if ( (GlobalStatus & 8) != 0 )
  {
    RtlInitUnicodeString(&SymbolicLinkName, DosDevices[HvProductType]);
    IoDeleteSymbolicLink(&SymbolicLinkName);
  }
  if ( (GlobalStatus & 1) != 0 )
    IoDeleteDevice(HvGlobalState->HvDevice);
  result = qword_140045688;
  if ( qword_140045688 )
  {
    result = qword_140045688(DriverObject, RegistryPath);
    qword_140045688 = 0i64;
  }
  return result;
}
