bool Avast::Util::IsEarlierThanWin10()
{
  return UKUSER_SHARED_DATA.NtMajorVersion < 0xA;
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