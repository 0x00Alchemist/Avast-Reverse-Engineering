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
