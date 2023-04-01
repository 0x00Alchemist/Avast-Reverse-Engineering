bool Avast::Util::IsEarlierThanWin10()
{
  return UKUSER_SHARED_DATA.NtMajorVersion < 0xA;
}

unsigned int __fastcall Avast::Util::StoreProcessTimes(__int64 process_handle)
{
  unsigned int result; // eax
  __int64 data_address; // rsi
  void *handle; // rcx
  __int64 counter; // rbx
  int error_code; // edi
  unsigned int shifted_result; // edi
  __int64 times_information; // r9
  unsigned __int8 index; // dl
  __int64 v10; // r8
  __int128 ProcessInformation[2]; // [rsp+30h] [rbp-38h] BYREF
  __int64 v12; // [rsp+78h] [rbp+10h] BYREF

  result = Avast::Memory::GetDataByIndex(&dword_180010B70, &v12);
  if ( (result & 0x80000000) != 0 )
    return result;
  data_address = v12;
  if ( !v12 || !*(v12 + 3) )
    return result;
  handle = *process_handle;
  counter = 0i64;
  memset(ProcessInformation, 0, sizeof(ProcessInformation));
  if ( qword_180010ED8 )
    result = qword_180010ED8(handle);
  else
    result = ZwQueryInformationProcess(handle, ProcessTimes, ProcessInformation, 0x20u, 0i64);
  if ( (result & 0x80000000) == 0 )
  {
    times_information = *&ProcessInformation[0];
LABEL_20:
    index = 0;
    while ( 1 )
    {
      result = index;
      v10 = data_address + 24i64 * index;
      if ( (*(v10 + 24) & 1) == 0 )
        break;
      if ( ++index >= 8u )
        return result;
    }
    *(v10 + 12) = *(process_handle + 16);
    result = *(process_handle + 20);
    *(v10 + 8) = result;
    *(v10 + 24) = 1;
    *(v10 + 16) = times_information;
    --*(data_address + 3);
    return result;
  }
  if ( result == 0x80000005 )
  {
    error_code = 0xE0010044;
  }
  else
  {
    shifted_result = result >> 30;
    if ( !(result >> 30) )
      shifted_result = 1;
    result = RtlNtStatusToDosError(result);
    while ( dword_18000D190[2 * counter] != result )
    {
      if ( ++counter >= 0x21 )
      {
        result = result;
        error_code = result | (shifted_result << 30) | 0x70000;
        goto LABEL_17;
      }
    }
    result = LOWORD(dword_18000D190[2 * counter + 1]);
    error_code = result | (shifted_result << 30) | 0x20010000;
  }
LABEL_17:
  if ( error_code >= 0 )
  {
    times_information = v12;
    goto LABEL_20;
  }
  return result;
}

__int64 __fastcall Avast::Util::GetErrorCode(unsigned int systemErrorStatus)
{
  unsigned int shiftResult;
  ULONG status;
  __int64 errorCodeIndex;

  if ( !systemErrorStatus )
    return 0i64;
  if ( systemErrorStatus == 0x80000005 )
    return 0xE0010044i64;
  shiftResult = systemErrorStatus >> 30;
  if ( !(systemErrorStatus >> 30) )
    shiftResult = 1;
  status = RtlNtStatusToDosError(systemErrorStatus);
  errorCodeIndex = 0i64;
  while ( dword_18000D190[2 * errorCodeIndex] != status )
  {
    if ( ++errorCodeIndex >= 0x21 )
      return status | (shiftResult << 30) | 0x70000;
  }
  return LOWORD(dword_18000D190[2 * errorCodeIndex + 1]) | (shiftResult << 30) | 0x20010000;
}

__int64 Avast::Util::ComputeValuesFromArray()
{
  __int64 numElements;
  int *arrayAddress;
  __int64 computeValueResult;

  numElements = 10;
  arrayAddress = &dword_18000B108;
  do
  {
    arrayAddress -= 6;
    computeValueResult = Avast::Memory::DeallocateMemory(arrayAddress);
    --numElements;
  }
  while ( numElements );
  return computeValueResult;
}

__int64 __fastcall Avast::Util::CallSpecificPPV(LPVOID *pPV, IID *rIID)
{
  LPVOID lpPVArg; 
  __int64 result; 
  __int64 v4; 
  LPVOID v5;

  v5 = 0i64;
  lpPVArg = *pPV;
  if ( *&rIID->Data1 == 0x40134DA92FABA4C7i64 && *rIID->Data4 == 0x850FD43FCC209796ui64 )
  {
    v5 = lpPVArg;
    result = (*(*lpPVArg + 8i64))(lpPVArg);
    v4 = v5;
  }
  else
  {
    result = (**lpPVArg)(lpPVArg, &qword_18000D970, &v5);
    v4 = v5;
    if ( result < 0 )
      v4 = 0i64;
    v5 = v4;
  }
  if ( v4 )
  {
    byte_18001117A = sub_180005830(*(*v4 + 56i64), sub_180005F40, &qword_1800110B0) >= 0;
    return (*(*v5 + 16i64))(v5);
  }
  return result;
}

bool __fastcall Avast::Util::CheckCLSID(CLSID *rCLSID)
{
  return (*&rCLSID->Data1 == 0x11D1F2A1C08AFD90i64 && *rCLSID->Data4 == 0x80381FC9A0005584ui64)
      || (*&rCLSID->Data1 == 0x11CFF6A89BA05972i64 && *rCLSID->Data4 == 0x398F0AC9A00042A4i64)
      || (*&rCLSID->Data1 == 0x4C90B1AE49B2791Ai64 && *rCLSID->Data4 == 0x89F807BA60E88E9Bui64)
      || (*&rCLSID->Data1 == 0x24500i64 && *rCLSID->Data4 == 0x46000000000000C0i64)
      || (*&rCLSID->Data1 == 0x6F03Ai64 && *rCLSID->Data4 == 0x46000000000000C0i64)
      || (*&rCLSID->Data1 == 0x209FFi64 && *rCLSID->Data4 == 0x46000000000000C0i64)
      || (*&rCLSID->Data1 == 0x21A20i64 && *rCLSID->Data4 == 0x46000000000000C0i64)
      || (*&rCLSID->Data1 == 0xD0A26i64 && *rCLSID->Data4 == 0x46000000000000C0i64)
      || (*&rCLSID->Data1 == 0x11D0D68D73A4C9C1i64 && *rCLSID->Data4 == 0xD9C80DC9A000BF98ui64)
      || (*&rCLSID->Data1 == 0x11CF5A9191493441i64 && *rCLSID->Data4 == 0x3B266000AA000087i64);
}