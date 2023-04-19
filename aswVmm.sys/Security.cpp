char __fastcall Security::HvIntegrityCheck(PVOID DriverStart, int DriverSize)
{
  char v2;
  struct_HvGlobalState *qword4B8;
  struct_HvGlobalState *v4;
  _QWORD *PoolWithTag;
  _QWORD *Allocated;
  _QWORD *p_qword4B8;
  __int64 v8;

  v2 = 0;
  KeEnterCriticalRegion();
  ExAcquireResourceExclusiveLite(&HvGlobalState->eresource188, 1u);
  qword4B8 = HvGlobalState->qword4B8;
  while ( qword4B8 != &HvGlobalState->qword4B8 )
  {
    v4 = qword4B8;
    qword4B8 = qword4B8->qword0;
    if ( *v4->gap10 == DriverStart && v4->osversioninfow18.dwOSVersionInfoSize == DriverSize )
      goto LABEL_10;
  }
  PoolWithTag = ExAllocatePoolWithTag(PagedPool, 0x20ui64, 'MMVA');
  Allocated = PoolWithTag;
  if ( !PoolWithTag )
    goto LABEL_11;
  PoolWithTag[2] = DriverStart;
  *(PoolWithTag + 6) = DriverSize;
  p_qword4B8 = &HvGlobalState->qword4B8;
  v8 = HvGlobalState->qword4B8;
  if ( *(v8 + 8) != &HvGlobalState->qword4B8 )
    __fastfail(3u);
  *Allocated = v8;
  Allocated[1] = p_qword4B8;
  *(v8 + 8) = Allocated;
  *p_qword4B8 = Allocated;
LABEL_10:
  v2 = 1;
LABEL_11:
  ExReleaseResourceLite(&HvGlobalState->eresource188);
  KeLeaveCriticalRegion();
  return v2;
}

bool __fastcall Security::CheckModuleIntegrity(unsigned __int64 buffer)
{
  bool checkResult;
  char *moduleBaseAddress;
  __int64 NtHeaders;
  char *dataDirectory;
  __int64 ExportDirRVA;
  unsigned int ExportDirSize;
  char *exportDataStartAddress;
  __int64 index;
  unsigned __int64 nameLengthValue;
  __int64 lastSlashIndex;
  char currentCharacterValue;
  char refVar13[16]; 
  PVOID driverStart;
  unsigned int driverSize; 

  checkResult = 0;
  if ( buffer )
  {
    moduleBaseAddress = Util::GetModuleBaseAddress(0i64, buffer, refVar13);
    if ( moduleBaseAddress )
    {
      if ( driverSize >= 64ui64 && *moduleBaseAddress == 'ZM' )
      {
        NtHeaders = *(moduleBaseAddress + 15);
        if ( driverSize >= (NtHeaders + 0x108) && *&moduleBaseAddress[NtHeaders] == 'EP' )
        {
          dataDirectory = 0i64;
          if ( *&moduleBaseAddress[NtHeaders + 0x84] > 6u )
            dataDirectory = &moduleBaseAddress[*&moduleBaseAddress[NtHeaders + 0xB8]];
          if ( dataDirectory )
          {
            if ( dataDirectory + 28 <= &moduleBaseAddress[driverSize] && *(dataDirectory + 3) == 2 )
            {
              ExportDirRVA = *(dataDirectory + 5);
              ExportDirSize = *(dataDirectory + 4);
              if ( driverSize >= (ExportDirSize + ExportDirRVA) && ExportDirSize >= 0x1C )
              {
                exportDataStartAddress = &moduleBaseAddress[ExportDirRVA];
                if ( *&moduleBaseAddress[ExportDirRVA] == 'SDSR' )
                {
                  index = ExportDirSize - 25;
                  nameLengthValue = index;
                  if ( !exportDataStartAddress[index + 24] )
                  {
                    lastSlashIndex = 0i64;
                    for ( index = index; index; --index )
                    {
                      currentCharacterValue = exportDataStartAddress[index + 23];
                      if ( currentCharacterValue == '\\' || currentCharacterValue == '/' )
                      {
                        lastSlashIndex = index;
                        break;
                      }
                    }
                    if ( lastSlashIndex + 3 <= nameLengthValue
                      && ((exportDataStartAddress[lastSlashIndex + 24] - 'A') & 0xDF) == 0
                      && ((exportDataStartAddress[lastSlashIndex + 25] - 'S') & 0xDF) == 0 )
                    {
                      checkResult = ((exportDataStartAddress[lastSlashIndex + 26] - 87) & 0xDF) == 0;
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  if ( checkResult )
    Security::HvIntegrityCheck(driverStart, driverSize);
  return checkResult;
}

ACCESS_MASK __fastcall Security::SetAccessMaskBySecurityInfo(
        SECURITY_INFORMATION SecurityInfo,
        ACCESS_MASK *DesiredAccess)
{
  ACCESS_MASK result; 

  result = 0;
  *DesiredAccess = 0;
  if ( (SecurityInfo & 3) != 0 )
  {
    result = 0x80000;
    *DesiredAccess = 0x80000;
  }
  if ( (SecurityInfo & 4) != 0 )
  {
    result |= 0x40000u;
    *DesiredAccess = result;
  }
  if ( (SecurityInfo & 8) != 0 )
  {
    result |= 0x1000000u;
    *DesiredAccess = result;
  }
  return result;
}

NTSTATUS __fastcall Security::SetSecurityObject(PVOID Object, PSECURITY_DESCRIPTOR *SecDesc)
{
  int v4; 
  NTSTATUS result; 
  NTSTATUS Status; 
  HANDLE Handle; 
  unsigned __int8 Owner; 
  SECURITY_INFORMATION SecurityInformation; 
  ACCESS_MASK DesiredAccess; 

  SecurityInformation = 0;
  DesiredAccess = 0;
  Handle = 0i64;
  v4 = *SecDesc;
  Owner = 0;
  if ( (v4 & 2) == 0 )
    return 0;
  result = Util::GetSecInfo(SecDesc[1], &Owner, &SecurityInformation);
  if ( result >= 0 )
  {
    Security::SetAccessMaskBySecurityInfo(SecurityInformation, &DesiredAccess);
    result = ObOpenObjectByPointer(Object, 0x200u, 0i64, DesiredAccess, IoDeviceObjectType, 0, &Handle);
    if ( result >= 0 )
    {
      Status = ZwSetSecurityObject(Handle, SecurityInformation, SecDesc[1]);
      ZwClose(Handle);
      return Status;
    }
  }
  return result;
}
