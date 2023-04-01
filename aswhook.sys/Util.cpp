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