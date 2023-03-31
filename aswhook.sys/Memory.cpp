BOOLEAN __fastcall Avast::Memory::FreeHeapMemory(void *Address)
{
  BOOLEAN result;

  if ( Address )
    return RtlFreeHeap(*(KeGetPcr()->NtTib.Self[1].ArbitraryUserPointer + 6), 0, Address);
  return result;
}

__int64 __fastcall Avast::Memory::DeallocateMemory(__int64 memory_handle)
{
  __int64 result;

  Avast::Memory::FreeHeapMemory(*(memory_handle + 16));
  result = 0;
  *memory_handle = 0;
  *(memory_handle + 8) = 0;
  *(memory_handle + 16) = 0;
  return result;
}

PVOID __fastcall Avast::Memory::AllocateHeapMemory(SIZE_T size)
{
  return RtlAllocateHeap(*(KeGetPcr()->NtTib.Self[1].ArbitraryUserPointer + 6), 0, size);
}

bool __fastcall Avast::Memory::IsAddressInMappedRange(PVOID mappingStartAddress, unsigned __int64 addressToCheck)
{
  unsigned __int64 v2;
  int status;
  __int64 peHeader;
  __int64 imageSizeOffset;
  __int64 memoryInfoStructPtr;
  __int64 dosHeader;
  ULONG_PTR bytesReaded;

  v2 = addressToCheck;
  status = NtQueryVirtualMemory(
                    0xFFFFFFFFFFFFFFFF,
                    mappingStartAddress,
                    MemoryBasicInformation,
                    &memoryInfoStructPtr,
                    0x30,
                    &bytesReaded);
  if ( status < 0 )
    GlobalFunctionStatus = RtlNtStatusToDosError(status);
  if ( *dosHeader != 0x5A4D )
    return 0;
  peHeader = *(dosHeader + 60);
  if ( *(peHeader + dosHeader) != 0x4550 )
    return 0;
  imageSizeOffset = *(peHeader + dosHeader + 0xE8);
  return v2 >= imageSizeOffset + dosHeader && v2 < dosHeader + imageSizeOffset + *(peHeader + dosHeader + 0xEC);
}

void Avast::Memory::ProtectRegions()
{
  _QWORD *baseAddressPtr;
  int ntProtectVMemResult;
  int ntFlushInstrCacheResult;
  ULONG oldProtection;
  SIZE_T numBytesToProtRef;
  PVOID baseAddrRef;

  baseAddressPtr = BaseAddress;
  if ( BaseAddress )
  {
    do
    {
      numBytesToProtRef = 0x10000;
      baseAddrRef = baseAddressPtr;
      ntProtectVMemResult = NtProtectVirtualMemory(
                              0xFFFFFFFFFFFFFFFF,
                              &baseAddrRef,
                              &numBytesToProtRef,
                              0x20,
                              &oldProtection);
      if ( ntProtectVMemResult < 0 )
        GlobalFunctionStatus = RtlNtStatusToDosError(ntProtectVMemResult);
      ntFlushInstrCacheResult = NtFlushInstructionCache(0xFFFFFFFFFFFFFFFF, baseAddressPtr, 0x10000);
      if ( ntFlushInstrCacheResult < 0 )
        GlobalFunctionStatus = RtlNtStatusToDosError(ntFlushInstrCacheResult);
      baseAddressPtr = baseAddressPtr[1];
    }
    while ( baseAddressPtr );
  }
}

__int64 Avast::Memory::SetProtection()
{
  _QWORD *v0;
  ULONG errorCode;
  int ntStatusCode;
  __int64 functionResult;
  ULONG oldProtection;
  SIZE_T numberOfBytes;
  PVOID baseAddress;

  if ( dword_18000AFF8 || _InterlockedCompareExchange(&dword_18000AFF8, KeGetPcr()->NtTib.Self[1].StackLimit, 0) )
    return 0x10DD;
  v0 = BaseAddress;
  errorCode = 0;
  qword_18000AFC0 = 0;
  qword_18000AFD0 = 0;
  qword_18000AFE8 = 0;
  if ( BaseAddress )
  {
    while ( 1 )
    {
      numberOfBytes = 0x10000;
      baseAddress = v0;
      ntStatusCode = NtProtectVirtualMemory(0xFFFFFFFFFFFFFFFF, &baseAddress, &numberOfBytes, 0x40u, &oldProtection);
      if ( ntStatusCode < 0 )
        break;
      v0 = v0[1];
      if ( !v0 )
        goto LABEL_8;
    }
    errorCode = RtlNtStatusToDosError(ntStatusCode);
    GlobalFunctionStatus = errorCode;
  }
LABEL_8:
  functionResult = errorCode;
  dword_18000AFFC = errorCode;
  return functionResult;
}

PVOID __fastcall Avast::Memory::FindReadableRegion(char *startAddress, unsigned __int64 sizeLimit)
{
  char *currentRegion;
  int v4;
  PVOID result;
  __int128 memoryInfoBuffer;
  __int128 baseProtectBuffer;
  __int128 regionSizeBuffer;
  ULONG_PTR returnedLength;

  currentRegion = startAddress;
  if ( startAddress )
    currentRegion = &startAddress[-startAddress + 0x10000];
  if ( currentRegion >= sizeLimit )
    return 0;
  while ( (currentRegion + 0x90000000) <= 0x10000000 )
  {
    currentRegion += 0x8000000;
LABEL_14:
    if ( currentRegion >= sizeLimit )
      return 0;
  }
  memoryInfoBuffer = 0;
  baseProtectBuffer = 0;
  regionSizeBuffer = 0;
  v4 = NtQueryVirtualMemory(
         0xFFFFFFFFFFFFFFFF,
         currentRegion,
         MemoryBasicInformation,
         &memoryInfoBuffer,
         0x30u,
         &returnedLength);
  if ( v4 >= 0 )
  {
    if ( !returnedLength )
      return 0;
    if ( regionSizeBuffer == 0x10000 && *(&baseProtectBuffer + 1) >= 0x10000u )
    {
      result = Avast::Memory::VirtualAlloc(*(&baseProtectBuffer + 1), currentRegion);
      if ( result )
        return result;
      currentRegion += 0x10000;
    }
    else
    {
      currentRegion = (*(&baseProtectBuffer + 1) + memoryInfoBuffer);
      if ( WORD4(baseProtectBuffer) + memoryInfoBuffer )
        currentRegion += 0x10000 - (WORD4(baseProtectBuffer) + memoryInfoBuffer);
    }
    goto LABEL_14;
  }
  GlobalFunctionStatus = RtlNtStatusToDosError(v4);
  return 0;
}

PVOID __fastcall Avast::Memory::FindMemoryAllocation(unsigned __int64 MemorySize, __int64 StartAddress)
{
  char *currentAddressPtr;
  char *lowestPossibleAddr;
  int status;
  __int64 allocatedMemSize;
  PVOID memAllocResult;
  __int128 memInfoStruct;
  __int128 stateVar;
  __int128 protectVar;
  ULONG_PTR retLen;

  currentAddressPtr = (StartAddress - 0x10000);
  lowestPossibleAddr = &currentAddressPtr[-currentAddressPtr];
  if ( !currentAddressPtr )
    lowestPossibleAddr = currentAddressPtr;
  if ( lowestPossibleAddr <= MemorySize )
    return 0;
  while ( (lowestPossibleAddr + 0x90000000) <= 0x10000000 )
  {
    lowestPossibleAddr -= 0x8000000;
LABEL_14:
    if ( lowestPossibleAddr <= MemorySize )
      return 0;
  }
  memInfoStruct = 0;
  stateVar = 0;
  protectVar = 0;
  status = NtQueryVirtualMemory(
             0xFFFFFFFFFFFFFFFF,
             lowestPossibleAddr,
             MemoryBasicInformation,
             &memInfoStruct,
             0x30u,
             &retLen);
  if ( status >= 0 )
  {
    if ( !retLen )
      return 0;
    if ( protectVar == 0x10000 && *(&stateVar + 1) >= 0x10000u )
    {
      memAllocResult = Avast::Memory::VirtualAlloc(allocatedMemSize, lowestPossibleAddr);
      if ( memAllocResult )
        return memAllocResult;
      lowestPossibleAddr -= 0x10000;
    }
    else
    {
      lowestPossibleAddr = (*(&memInfoStruct + 1) - 0x10000 - WORD4(memInfoStruct));
      if ( !WORD4(memInfoStruct) )
        lowestPossibleAddr = (*(&memInfoStruct + 1) - 0x10000);
    }
    goto LABEL_14;
  }
  GlobalFunctionStatus = RtlNtStatusToDosError(status);
  return 0;
}

PVOID __fastcall Avast::Memory::VirtualAlloc(__int64 Size, void *baseAddress)
{
  int status;
  __int64 allocSize[2];
  PVOID BaseAddress;

  BaseAddress = baseAddress;
  allocSize[0] = 0x10000;
  status = NtAllocateVirtualMemory(0xFFFFFFFFFFFFFFFF, &BaseAddress, 0, allocSize, 0x3000u, 0x40u);
  if ( status >= 0 )
    return BaseAddress;
  GlobalFunctionStatus = RtlNtStatusToDosError(status);
  return 0;
}

char *__fastcall Avast::Memory::CopyData(
        __int64 sourceMemory,
        unsigned int *sourceMemorySize,
        char *targetMemory,
        _BYTE *flags)
{
  unsigned int v4;
  __int64 v6;
  unsigned int v7;
  bool v11;
  unsigned int v12;
  int v13;
  int v14;
  __int64 v15;
  char v16;
  char v17;
  __int64 v18;
  char *v19;
  _BYTE *v20;
  _BYTE *v21;
  int v22;
  int v23;
  int v24;
  __int64 v25;
  __int64 v26;
  __int64 v27;

  v4 = *sourceMemorySize;
  v6 = HIWORD(*sourceMemorySize) & 0xF;
  v7 = *sourceMemorySize >> 8;
  if ( (*sourceMemorySize & 0x2000000) != 0 )
  {
    v11 = *(sourceMemory + 4) == 0;
  }
  else
  {
    if ( *(sourceMemory + 8) )
    {
      v12 = ((v4 >> 25) & 4) + (v7 & 0xF);
      goto LABEL_9;
    }
    v11 = *sourceMemory == 0;
  }
  if ( !v11 )
    LOBYTE(v7) = *sourceMemorySize >> 12;
  v12 = v7 & 0xF;
LABEL_9:
  v13 = (v4 >> 20) & 0xF;
  v14 = v12 - v13;
  if ( !v6 )
    goto LABEL_20;
  v15 = flags[v6];
  v16 = byte_18000D040[v15];
  v12 += v16 & 0xF;
  if ( (v16 & 0x10) != 0 )
  {
    if ( (flags[(v6 + 1)] & 7) == 5 )
    {
      v17 = v15 & 0xC0;
      switch ( v17 )
      {
        case 0:
          goto LABEL_16;
        case 0x40:
          v14 = ++v12 - v13;
          goto LABEL_20;
        case 0x80:
LABEL_16:
          v12 += 4;
          break;
      }
    }
    v14 = v12 - v13;
  }
  else if ( (v16 & 0x20) != 0 )
  {
    v13 = v6 + 1;
    v14 = 4;
  }
LABEL_20:
  v18 = v12;
  memcpy(targetMemory, flags, v12);
  if ( !v13 )
    goto LABEL_43;
  v19 = &targetMemory[v13];
  switch ( v14 )
  {
    case 1:
      v27 = *v19;
      v20 = &flags[v18 + v27];
      v21 = &flags[v27 - targetMemory];
      goto LABEL_39;
    case 2:
      v26 = *v19;
      v20 = &flags[v18 + v26];
      v21 = &flags[v26 - targetMemory];
LABEL_36:
      *v19 = v21;
      if ( (v21 + 0x8000) > 0xFFFF )
        **(sourceMemory + 40) = 2;
      goto LABEL_41;
    case 4:
      v25 = *v19;
      v20 = &flags[v25 + v18];
      v21 = (v25 + flags - targetMemory);
LABEL_33:
      *v19 = v21;
      if ( (v21 + 0x80000000) > 0xFFFFFFFF )
        **(sourceMemory + 40) = 0;
      goto LABEL_41;
    case 8:
      v20 = &flags[v18 + *v19];
      v21 = &flags[*v19 - targetMemory];
      goto LABEL_31;
  }
  v20 = &flags[v18];
  v21 = (flags - targetMemory);
  v22 = v14 - 1;
  if ( !v22 )
  {
LABEL_39:
    *v19 = v21;
    if ( (v21 + 128) > 0xFF )
      **(sourceMemory + 40) = 3;
    goto LABEL_41;
  }
  v23 = v22 - 1;
  if ( !v23 )
    goto LABEL_36;
  v24 = v23 - 2;
  if ( !v24 )
    goto LABEL_33;
  if ( v24 == 4 )
LABEL_31:
    *v19 = v21;
LABEL_41:
  **(sourceMemory + 32) = v20;
  if ( (*sourceMemorySize & 0xF00000) == 0 )
    **(sourceMemory + 32) = 0;
LABEL_43:
  if ( (v4 & 0x4000000) != 0 )
    **(sourceMemory + 40) = -**(sourceMemory + 40);
  if ( (v4 & 0x1000000) != 0 )
    **(sourceMemory + 32) = -1;
  return &flags[v18];
}

char *__fastcall Avast::Memory::Copy(
        __int64 destinationMemoryLocation,
        __int64 numBytesToCopy,
        char *sourceBuffer,
        _BYTE *flags)
{
  unsigned int *sourceMemoryLocation;

  sourceMemoryLocation = &unk_18000D010;
  if ( (flags[1] & 0x38) != 0 )
    sourceMemoryLocation = &unk_18000F170;
  return Avast::Memory::CopyData(destinationMemoryLocation, sourceMemoryLocation, sourceBuffer, flags);
}

__int64 __fastcall Avast::Memory::SubSystem::AllocateTibMapSlot(ULONG *localDataIndex)
{
  struct _NT_TIB *selfPtr;
  unsigned int v4;
  PRTL_BITMAP *arbitraryUserPtr;
  ULONG clearBitsAndSetVal;
  ULONG slotValue;
  ULONG ClearBitsAndSet;
  _QWORD *subsystemTibPtr;
  PVOID heapPtr;
  __int64 v11;

  if ( *localDataIndex != -1 )
    return 0xC000000D;
  selfPtr = KeGetPcr()->NtTib.Self;
  v4 = 0;
  arbitraryUserPtr = selfPtr[1].ArbitraryUserPointer;
  RtlAcquirePebLock();
  clearBitsAndSetVal = RtlFindClearBitsAndSet(arbitraryUserPtr[15], 1u, 0);
  slotValue = clearBitsAndSetVal;
  if ( clearBitsAndSetVal != -1 )
  {
    *(&selfPtr[93].ArbitraryUserPointer + clearBitsAndSetVal) = 0;
    goto LABEL_15;
  }
  ClearBitsAndSet = RtlFindClearBitsAndSet(arbitraryUserPtr[71], 1u, 0);
  slotValue = ClearBitsAndSet;
  if ( ClearBitsAndSet != -1 )
  {
    if ( ClearBitsAndSet == 1023 )
    {
      RtlClearBits(arbitraryUserPtr[71], 0x3FFu, 1u);
      goto LABEL_7;
    }
    subsystemTibPtr = selfPtr[107].SubSystemTib;
    if ( subsystemTibPtr
      || (heapPtr = RtlAllocateHeap(*(KeGetPcr()->NtTib.Self[1].ArbitraryUserPointer + 6), 8u, 0x2000u),
          selfPtr[107].SubSystemTib = heapPtr,
          (subsystemTibPtr = heapPtr) != 0)
      || (RtlClearBits(arbitraryUserPtr[71], slotValue, 1u),
          subsystemTibPtr = selfPtr[107].SubSystemTib,
          slotValue = -1,
          v4 = 0xC0000017,
          subsystemTibPtr) )
    {
      v11 = slotValue;
      slotValue += 64;
      subsystemTibPtr[v11] = 0;
    }
    if ( slotValue == -1 )
      goto LABEL_16;
LABEL_15:
    *localDataIndex = slotValue;
    goto LABEL_16;
  }
LABEL_7:
  v4 = 0xC000009A;
LABEL_16:
  RtlReleasePebLock();
  return v4;
}

__int64 __fastcall Avast::Memory::SubSystem::GetDataByIndex(
        unsigned int *threadLocalDataIndex,
        _QWORD *threadLocalDataValue)
{
  struct _NT_TIB *Tib;
  __int64 v3;
  __int64 v4;
  __int64 result;
  _QWORD *SubSystemTib;

  Tib = KeGetPcr()->NtTib.Self;
  v3 = *threadLocalDataIndex;
  if ( v3 >= 0x40 )
  {
    if ( v3 < 0x440 )
    {
      SubSystemTib = Tib[107].SubSystemTib;
      if ( SubSystemTib )
        *threadLocalDataValue = SubSystemTib[(v3 - 64)];
      else
        *threadLocalDataValue = 0;
      return 0;
    }
    else
    {
      return 0xC000000D;
    }
  }
  else
  {
    v4 = *(&Tib[93].ArbitraryUserPointer + v3);
    result = 0;
    *threadLocalDataValue = v4;
  }
  return result;
}

__int64 __fastcall Avast::Memory::SubSystem::SetIndex(unsigned int *index, __int64 value)
{
  struct _NT_TIB *_ntTibPtr;
  __int64 subsystemIndex;
  __int64 offsetFrom64thIndex;
  _QWORD *SubSystemTib;
  PVOID heapPtr;

  _ntTibPtr = KeGetPcr()->NtTib.Self;
  subsystemIndex = *index;
  if ( subsystemIndex < 0x40 )
  {
    *(&_ntTibPtr[93].ArbitraryUserPointer + subsystemIndex) = value;
    return 0;
  }
  else
  {
    offsetFrom64thIndex = (subsystemIndex - 64);
    if ( offsetFrom64thIndex >= 0x400 )
    {
      return 0xC000000D;
    }
    else
    {
      SubSystemTib = _ntTibPtr[107].SubSystemTib;
      if ( !SubSystemTib )
      {
        RtlAcquirePebLock();
        if ( !_ntTibPtr[107].SubSystemTib )
        {
          heapPtr = RtlAllocateHeap(*(KeGetPcr()->NtTib.Self[1].ArbitraryUserPointer + 6), 8u, 0x2000u);
          _ntTibPtr[107].SubSystemTib = heapPtr;
          if ( !heapPtr )
          {
            RtlReleasePebLock();
            return 0xC0000017;
          }
        }
        RtlReleasePebLock();
        SubSystemTib = _ntTibPtr[107].SubSystemTib;
      }
      SubSystemTib[offsetFrom64thIndex] = value;
      return 0;
    }
  }
}