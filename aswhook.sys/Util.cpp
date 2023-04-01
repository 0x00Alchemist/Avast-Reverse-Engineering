bool Avast::Util::IsEarlierThanWin10()
{
  return UKUSER_SHARED_DATA.NtMajorVersion < 0xA;
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