__int64 __fastcall Avast::Hook::NtContinue(__int64 ThreadContext, unsigned __int8 RaiseAlert)
{
  void **fileHandlePtr;
  PHANDLE fileHandleRef;
  void *handleValue;
  int status;
  struct _IO_STATUS_BLOCK ioStatusBlockStruct;
  _BYTE *wasDeviceOpenedFlagRef;

  if ( ThreadContext
    && *(ThreadContext + 0xF8) == qword_180011198
    && Avast::Memory::GetDataByIndex(&dword_180010B70, &wasDeviceOpenedFlagRef) >= 0
    && wasDeviceOpenedFlagRef
    && *wasDeviceOpenedFlagRef != 1 )
  {
    fileHandlePtr = FileHandle;
    fileHandleRef = FileHandle;
    *wasDeviceOpenedFlagRef = 1;
    if ( Avast::CreateFile(fileHandleRef) >= 0 )
    {
      handleValue = *fileHandlePtr;
      ioStatusBlockStruct = 0i64;
      status = ZwDeviceIoControlFile(handleValue, 0i64, 0i64, 0i64, &ioStatusBlockStruct, 0x53606180u, 0i64, 0, 0i64, 0);
      if ( status < 0 )
        RtlNtStatusToDosError(status);
    }
    if ( Avast::Memory::GetDataByIndex(&dword_180010B70, &wasDeviceOpenedFlagRef) >= 0
      && wasDeviceOpenedFlagRef
      && *wasDeviceOpenedFlagRef )
    {
      *wasDeviceOpenedFlagRef = 0;
    }
  }
  return oNtContinue(ThreadContext, RaiseAlert);
}

__int64 __fastcall Avast::Hook::NtOpenThread(HANDLE *threadHandle, int desiredAccess)
{
  int status;
  void **fileHandlePtr;
  struct _NT_TIB *selfTibPtr;
  int stackLimitVal;
  void *v8;
  int v9;
  struct _IO_STATUS_BLOCK IoStatusBlock;
  int InputBuffer[6];
  _BYTE *v13;
  char ThreadInformation[16];
  PVOID v15;
  int v16;

  status = oNtOpenThread(threadHandle, desiredAccess);
  if ( status >= 0
    && (desiredAccess & 0x32) != 0
    && Avast::Memory::GetDataByIndex(&dword_180010B70, &IoStatusBlock) >= 0
    && IoStatusBlock.Pointer
    && *IoStatusBlock.Pointer != 1 )
  {
    *IoStatusBlock.Pointer = 1;
    if ( ZwQueryInformationThread(*threadHandle, ThreadBasicInformation, ThreadInformation, 0x30u, 0i64) >= 0
      && KeGetPcr()->NtTib.Self[1].StackBase != v15 )
    {
      fileHandlePtr = FileHandle;
      selfTibPtr = KeGetPcr()->NtTib.Self;
      InputBuffer[0] = selfTibPtr[1].StackBase;
      InputBuffer[4] = desiredAccess;
      stackLimitVal = selfTibPtr[1].StackLimit;
      InputBuffer[2] = v15;
      InputBuffer[1] = stackLimitVal;
      InputBuffer[3] = v16;
      if ( Avast::CreateFile(FileHandle) >= 0 )
      {
        v8 = *fileHandlePtr;
        IoStatusBlock = 0i64;
        v9 = ZwDeviceIoControlFile(v8, 0i64, 0i64, 0i64, &IoStatusBlock, 0x53606160u, InputBuffer, 0x14u, 0i64, 0);
        if ( v9 < 0 )
          RtlNtStatusToDosError(v9);
      }
    }
    if ( Avast::Memory::GetDataByIndex(&dword_180010B70, &v13) >= 0 && v13 && *v13 )
      *v13 = 0;
  }
  return status;
}

__int64 __fastcall Avast::Hook::NtSuspendThread(HANDLE ThreadHandle)
{
  unsigned int status;
  void **v3; 
  struct _NT_TIB *Self;
  int StackLimit; 
  void *v6;
  int v7;
  int InputBuffer[4];
  struct _IO_STATUS_BLOCK IoStatusBlock;
  char ThreadInformation[16]; 
  PVOID v12;
  int v13; 
  _BYTE *v14; 
  _BYTE *v15;

  status = oNtSuspendThread(ThreadHandle);
  if ( Avast::Memory::GetDataByIndex(&dword_180010B70, &v14) >= 0 && v14 && *v14 != 1 )
  {
    *v14 = 1;
    if ( ZwQueryInformationThread(ThreadHandle, ThreadBasicInformation, ThreadInformation, 0x30u, 0i64) >= 0
      && KeGetPcr()->NtTib.Self[1].StackBase != v12 )
    {
      v3 = FileHandle;
      Self = KeGetPcr()->NtTib.Self;
      InputBuffer[0] = Self[1].StackBase;
      StackLimit = Self[1].StackLimit;
      InputBuffer[2] = v12;
      InputBuffer[1] = StackLimit;
      InputBuffer[3] = v13;
      if ( Avast::CreateFile(FileHandle) >= 0 )
      {
        v6 = *v3;
        IoStatusBlock = 0i64;
        v7 = ZwDeviceIoControlFile(v6, 0i64, 0i64, 0i64, &IoStatusBlock, 0x53606188u, InputBuffer, 0x10u, 0i64, 0);
        if ( v7 < 0 )
          RtlNtStatusToDosError(v7);
      }
    }
    if ( Avast::Memory::GetDataByIndex(&dword_180010B70, &v15) >= 0 && v15 && *v15 )
      *v15 = 0;
  }
  return status;
}

__int64 __fastcall Avast::Hook::NtCreateUserProcess(
        __int64 *processHandle,
        HANDLE *threadHandle,
        __int64 parentProcessHandle,
        __int64 inheritFromParentFlag,
        __int64 creationFlags,
        __int64 argumentList,
        int argumentsLength)
{
  __int64 result; 
  unsigned int resultCode;
  __int64 tempProcessHandle; 
  __int64 threadInformationArray[2];
  int firstValueInThreadInfoArray; 
  int secondValueInThreadInfoArray; 
  char ThreadInformation[16];
  int v16;
  int v17;

  result = oNtCreateUserProcess(
             processHandle,
             threadHandle,
             parentProcessHandle,
             inheritFromParentFlag,
             creationFlags,
             argumentList,
             argumentsLength);
  resultCode = result;
  if ( result >= 0 )
  {
    if ( ZwQueryInformationThread(*threadHandle, ThreadBasicInformation, ThreadInformation, 0x30u, 0i64) >= 0 )
    {
      tempProcessHandle = *processHandle;
      threadInformationArray[1] = *threadHandle;
      firstValueInThreadInfoArray = v16;
      threadInformationArray[0] = tempProcessHandle;
      secondValueInThreadInfoArray = v17;
      Avast::Util::StoreProcessTimes(threadInformationArray);
    }
    return resultCode;
  }
  return result;
}

__int64 __fastcall Avast::Hook::NtNotifyChangeKey(
        __int64 keyHandle,
        __int64 eventHandle,
        __int64 apcRoutine,
        __int64 apcRoutineContext,
        __int64 ioStatusBlock,
        int notifyFilter,
        char watchSubtree,
        __int64 regChangesDataBuffer,
        int regChangesDataBufferLength,
        char asynchronous)
{
  __int64 v14;
  int v16;
  __int64 v17[2]; 

  if ( Avast::Memory::GetDataByIndex(&dword_180010B70, v17) < 0 || !v17[0] || *v17[0] == 1 )
    return oNtNotifyChangeKey(
             keyHandle,
             eventHandle,
             apcRoutine,
             apcRoutineContext,
             ioStatusBlock,
             notifyFilter,
             watchSubtree,
             regChangesDataBuffer,
             regChangesDataBufferLength,
             asynchronous);
  *v17[0] = 1;
  Avast::Client::ReadData(v14, keyHandle, &v16);
  if ( Avast::Memory::GetDataByIndex(&dword_180010B70, v17) >= 0 && v17[0] )
  {
    if ( *v17[0] )
      *v17[0] = 0;
  }
  if ( v16 == 0xC0000022 )
    return 0xC0000022i64;
  else
    return oNtNotifyChangeKey(
             keyHandle,
             eventHandle,
             apcRoutine,
             apcRoutineContext,
             ioStatusBlock,
             notifyFilter,
             watchSubtree,
             regChangesDataBuffer,
             regChangesDataBufferLength,
             asynchronous);
}

__int64 __fastcall Avast::Hook::NtTerminateThread(HANDLE ThreadHandle, int ExitStatus)
{
  void **v4; 
  struct _NT_TIB *Self;
  int StackLimit;
  void *v7;
  int v8;
  struct _IO_STATUS_BLOCK IoStatusBlock;
  int InputBuffer[6]; 
  char ThreadInformation[16]; 
  PVOID v13; 
  int v14; 
  _BYTE *v15; 
  _BYTE *v16; 

  if ( Avast::Memory::GetDataByIndex(&dword_180010B70, &v15) >= 0 && v15 && *v15 != 1 )
  {
    *v15 = 1;
    if ( ZwQueryInformationThread(ThreadHandle, ThreadBasicInformation, ThreadInformation, 0x30u, 0i64) >= 0
      && KeGetPcr()->NtTib.Self[1].StackBase != v13 )
    {
      v4 = FileHandle;
      Self = KeGetPcr()->NtTib.Self;
      InputBuffer[0] = Self[1].StackBase;
      InputBuffer[4] = ExitStatus;
      StackLimit = Self[1].StackLimit;
      InputBuffer[2] = v13;
      InputBuffer[1] = StackLimit;
      InputBuffer[3] = v14;
      if ( Avast::CreateFile(FileHandle) >= 0 )
      {
        v7 = *v4;
        IoStatusBlock = 0i64;
        v8 = ZwDeviceIoControlFile(v7, 0i64, 0i64, 0i64, &IoStatusBlock, 0x5360618Cu, InputBuffer, 0x14u, 0i64, 0);
        if ( v8 < 0 )
          RtlNtStatusToDosError(v8);
      }
    }
    if ( Avast::Memory::GetDataByIndex(&dword_180010B70, &v16) >= 0 && v16 && *v16 )
      *v16 = 0;
  }
  return oNtTerminateThread(ThreadHandle, ExitStatus);
}

__int64 __fastcall Avast::Hook::NtTerminateProcess(__int64 ProcessHandle, unsigned int exitStatus)
{
  void **fHandle; 
  struct _NT_TIB *pcrTibSelf; 
  void *devPtr; 
  int statusVal; 
  struct _IO_STATUS_BLOCK iostatusBlkStructPtr; 
  int inBufferArrayPtr[2]; 
  __int64 v12; 
  __int64 process_handle2;
  unsigned int exit_status2;
  _BYTE *dataOneBytePtrName; 
  _BYTE *dataTwoBytePtrName; 

  if ( (ProcessHandle - 1) <= 0xFFFFFFFFFFFFFFFDui64
    && Avast::Memory::GetDataByIndex(&dword_180010B70, &dataOneBytePtrName) >= 0
    && dataOneBytePtrName
    && *dataOneBytePtrName != 1 )
  {
    *dataOneBytePtrName = 1;
    fHandle = FileHandle;
    pcrTibSelf = KeGetPcr()->NtTib.Self;
    inBufferArrayPtr[0] = pcrTibSelf[1].StackBase;
    v12 = 0i64;
    exit_status2 = exitStatus;
    inBufferArrayPtr[1] = pcrTibSelf[1].StackLimit;
    process_handle2 = ProcessHandle;
    if ( Avast::CreateFile(FileHandle) >= 0 )
    {
      devPtr = *fHandle;
      iostatusBlkStructPtr = 0i64;
      statusVal = ZwDeviceIoControlFile(
                    devPtr,
                    0i64,
                    0i64,
                    0i64,
                    &iostatusBlkStructPtr,
                    0x5360616Cu,
                    inBufferArrayPtr,
                    0x20u,
                    0i64,
                    0);
      if ( statusVal < 0 )
        RtlNtStatusToDosError(statusVal);
    }
    if ( Avast::Memory::GetDataByIndex(&dword_180010B70, &dataTwoBytePtrName) >= 0
      && dataTwoBytePtrName
      && *dataTwoBytePtrName )
    {
      *dataTwoBytePtrName = 0;
    }
  }
  return oNtTerminateProcess(ProcessHandle, exitStatus);
}

__int64 __fastcall Avast::Hook::NtSuspendProcess(unsigned int ProcessHandle)
{
  unsigned int status; 
  void **v3; 
  struct _NT_TIB *Self;
  void *v5;
  int v6; 
  struct _IO_STATUS_BLOCK IoStatusBlock; 
  int InputBuffer[2]; 
  __int64 v10; 
  __int64 v11; 
  _BYTE *v12; 
  _BYTE *v13; 

  status = oNtSuspendProcess();
  if ( Avast::Memory::GetDataByIndex(&dword_180010B70, &v12) >= 0 && v12 && *v12 != 1 )
  {
    *v12 = 1;
    v3 = FileHandle;
    Self = KeGetPcr()->NtTib.Self;
    InputBuffer[0] = Self[1].StackBase;
    v10 = 0i64;
    InputBuffer[1] = Self[1].StackLimit;
    v11 = ProcessHandle;
    if ( Avast::CreateFile(FileHandle) >= 0 )
    {
      v5 = *v3;
      IoStatusBlock = 0i64;
      v6 = ZwDeviceIoControlFile(v5, 0i64, 0i64, 0i64, &IoStatusBlock, 0x53606170u, InputBuffer, 0x18u, 0i64, 0);
      if ( v6 < 0 )
        RtlNtStatusToDosError(v6);
    }
    if ( Avast::Memory::GetDataByIndex(&dword_180010B70, &v13) >= 0 && v13 && *v13 )
      *v13 = 0;
  }
  return status;
}

__int64 __fastcall Avast::Hook::NtSetInformationProcess(
        char *procHandle,
        unsigned int processInfoClass,
        __int64 infoProcess,
        unsigned int infoLength)
{
  __int64 numOne;
  int info_process;
  int errOne;
  int errTwo;
  ULONG resOne;
  __int64 index1;
  int num2;
  void **v15;
  void *v16;
  int v17;
  struct _IO_STATUS_BLOCK IoStatusBlock;
  char ProcessInformation[32];
  int v21;
  _BYTE *inputbuffer;

  if ( (procHandle - 1) > 0xFFFFFFFFFFFFFFFDui64
    || !infoProcess
    || processInfoClass != 0x28
    || Avast::Memory::GetDataByIndex(&dword_180010B70, &inputbuffer) < 0
    || !inputbuffer
    || *inputbuffer == 1 )
  {
    return oNtSetInformationProcess(procHandle, processInfoClass, infoProcess, infoLength);
  }
  *inputbuffer = 1;
  numOne = processInfoClass + 8;
  if ( qword_180010ED8 )
    info_process = (qword_180010ED8)(procHandle, 0i64, ProcessInformation, numOne, 0i64);
  else
    info_process = ZwQueryInformationProcess(procHandle, ProcessBasicInformation, ProcessInformation, numOne, 0i64);
  if ( info_process >= 0 )
  {
    num2 = v21;
  }
  else
  {
    if ( info_process == 0x80000005 )
    {
      errOne = 0xE0010044;
    }
    else
    {
      errTwo = info_process >> 0x1E;
      if ( !(info_process >> 0x1E) )
        errTwo = 1;
      resOne = RtlNtStatusToDosError(info_process);
      index1 = 0i64;
      while ( dword_18000D190[2 * index1] != resOne )
      {
        if ( ++index1 >= 0x21 )
        {
          errOne = resOne | (errTwo << 30) | 0x70000;
          goto LABEL_20;
        }
      }
      errOne = LOWORD(dword_18000D190[2 * index1 + 1]) | (errTwo << 30) | 0x20010000;
    }
LABEL_20:
    if ( errOne < 0 )
      goto LABEL_26;
    num2 = inputbuffer;
  }
  v15 = FileHandle;
  LODWORD(inputbuffer) = num2;
  if ( Avast::CreateFile(FileHandle) >= 0 )
  {
    v16 = *v15;
    IoStatusBlock = 0i64;
    v17 = ZwDeviceIoControlFile(v16, 0i64, 0i64, 0i64, &IoStatusBlock, 0x53606190u, &inputbuffer, 4u, 0i64, 0);
    if ( v17 < 0 )
      RtlNtStatusToDosError(v17);
  }
LABEL_26:
  if ( Avast::Memory::GetDataByIndex(&dword_180010B70, &inputbuffer) >= 0 && inputbuffer && *inputbuffer )
    *inputbuffer = 0;
  return oNtSetInformationProcess(procHandle, processInfoClass, infoProcess, infoLength);
}

__int64 __fastcall Avast::Hook::NtCreateTimer(
        PHANDLE HandleTimer,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES pObjectAttributes,
        TIMER_TYPE TimerType)
{
  __int64 v8; 
  _BYTE *DataIndexByRef; 
  __int64 v11;

  if ( Avast::Memory::GetDataByIndex(&dword_180010B70, &DataIndexByRef) >= 0 && DataIndexByRef && *DataIndexByRef != 1 )
  {
    *DataIndexByRef = 1;
    if ( pObjectAttributes )
    {
      sub_180008EF0(&DataIndexByRef, pObjectAttributes);
      if ( v11 )
      {
        if ( DataIndexByRef )
          sub_1800070B0(v8, 6, DesiredAccess, DataIndexByRef, v11);
      }
    }
    if ( Avast::Memory::GetDataByIndex(&dword_180010B70, &DataIndexByRef) >= 0 && DataIndexByRef && *DataIndexByRef )
      *DataIndexByRef = 0;
  }
  return oNtCreateTimer(HandleTimer, DesiredAccess, pObjectAttributes, TimerType);
}

__int64 __fastcall Avast::Hook::NtOpenTimer(
        PHANDLE TimerHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES pObjectAttributes)
{
  unsigned __int64 v6; 
  unsigned __int16 *v7; 
  unsigned int v8;
  _QWORD *v9;
  __int64 v10; 
  unsigned __int16 *v11; 
  unsigned __int16 v12; 
  bool v13; 
  int v14; 
  __int64 v15; 
  char *v16; 
  __int64 Heap; 
  void *Src; 
  unsigned __int64 v20; 
  _BYTE *DataByIndex; 

  if ( Avast::Memory::GetDataByIndex(&dword_180010B70, &DataByIndex) >= 0 && DataByIndex && *DataByIndex != 1 )
  {
    *DataByIndex = 1;
    if ( pObjectAttributes )
    {
      sub_180008EF0(&Src, pObjectAttributes);
      v6 = v20;
      if ( v20 )
      {
        v7 = Src;
        if ( Src )
        {
          RtlAcquireSRWLockShared(&SRWLock);
          v8 = 0;
          v9 = &unk_180011238;
          while ( 1 )
          {
            v10 = *(v9 - 2);
            if ( v10 == v6 && *v9 )
            {
              v11 = v7;
              if ( v10 )
              {
                while ( 1 )
                {
                  v12 = *(v11 + *v9 - v7);
                  v13 = v12 < *v11;
                  if ( v12 != *v11 )
                    break;
                  ++v11;
                  if ( !--v10 )
                    goto LABEL_13;
                }
                v14 = 1;
                if ( v13 )
                  v14 = -1;
              }
              else
              {
LABEL_13:
                v14 = 0;
              }
              if ( !v14 )
                break;
            }
            ++v8;
            v9 += 3;
            if ( v8 >= 0xA )
            {
              RtlReleaseSRWLockShared(&SRWLock);
              if ( v7 && v6 )
              {
                RtlAcquireSRWLockExclusive(&SRWLock);
                v16 = &SRWLock + 24 * dword_180011318;
                if ( *(v16 + 2) >= v6 )
                  goto LABEL_21;
                Avast::Memory::FreeHeap(*(v16 + 3));
                *(v16 + 1) = 0i64;
                *(v16 + 2) = 0i64;
                *(v16 + 3) = 0i64;
                Heap = Avast::Memory::AllocateHeap(saturated_mul(v6, 2ui64));
                *(v16 + 3) = Heap;
                if ( Heap )
                {
                  *(v16 + 2) = v6;
LABEL_21:
                  memcpy(*(v16 + 3), v7, 2 * v6);
                  *(v16 + 1) = v6;
                  dword_180011318 = (dword_180011318 + 1) % 0xAu;
                }
                RtlReleaseSRWLockExclusive(&SRWLock);
              }
              Avast::Client::SendIoControlRequest(v15, 0x80000006, DesiredAccess, v7, v6);
              goto LABEL_24;
            }
          }
          RtlReleaseSRWLockShared(&SRWLock);
        }
      }
    }
LABEL_24:
    if ( Avast::Memory::GetDataByIndex(&dword_180010B70, &DataByIndex) >= 0 && DataByIndex && *DataByIndex )
      *DataByIndex = 0;
  }
  return oNtOpenTimer(TimerHandle, DesiredAccess, pObjectAttributes);
}

void __fastcall Avast::Hook::RegisterRawInputDevicesInternal(
        RAWINPUTDEVICE *pRawInputDevices,
        unsigned int uiNumDevices)
{
  unsigned int i; 
  int usUsage; 
  int HIDUsage; 
  int v7; 

  i = 0;
  while ( i < uiNumDevices )
  {
    usUsage = 0;
    if ( (pRawInputDevices[i].dwFlags & 0x100) != 0 && pRawInputDevices[i].usUsagePage == 1 )
      usUsage = pRawInputDevices[i].usUsage;

    HIDUsage = usUsage - 1;
    if ( HIDUsage && (v7 = HIDUsage - 1) != 0 )
    {
      if ( (v7 - 4) > 1 )
        goto LABEL_11;
      Avast::Hook::SetWindowsHookExInternal(2, 0, 0i64, 0);
      ++i;
    }
    else
    {
      Avast::Hook::SetWindowsHookExInternal(7, 0, 0i64, 0);
LABEL_11:
      ++i;
    }
  }
}

__int64 __fastcall Avast::Hook::RegisterRawInputDevicesHook(
        RAWINPUTDEVICE *pRawInputDevices,
        unsigned int uiNumDevices,
        unsigned int cbSize)
{
  Avast::Hook::RegisterRawInputDevicesInternal(pRawInputDevices, uiNumDevices);
  return oRegisterRawInputDevices(pRawInputDevices, uiNumDevices, cbSize);
}

_BYTE *__fastcall Avast::Hook::SetWindowsHookExInternal(int HookId, int ThreadId, LPVOID lpHookFunction, int a4)
{
  _BYTE *result; 
  void **v9; 
  PHANDLE FileHandle; 
  void *Handle;
  NTSTATUS Status; 
  _BYTE *DataByIndex;
  struct _IO_STATUS_BLOCK IoStatusBlock;
  int InputBuffer[2];
  LPVOID v16;
  int v17;

  result = Avast::Memory::GetDataByIndex(&dword_180010B70, &DataByIndex);
  if ( result >= 0 )
  {
    result = DataByIndex;
    if ( DataByIndex )
    {
      if ( *DataByIndex != 1 )
      {
        v9 = ::FileHandle;
        FileHandle = ::FileHandle;
        *DataByIndex = 1;
        InputBuffer[0] = HookId;
        InputBuffer[1] = ThreadId;
        v16 = lpHookFunction;
        v17 = a4;
        if ( Avast::CreateFile(FileHandle) >= 0 )
        {
          Handle = *v9;
          IoStatusBlock = 0i64;
          Status = ZwDeviceIoControlFile(
                     Handle,
                     0i64,
                     0i64,
                     0i64,
                     &IoStatusBlock,
                     0x53606158u,
                     InputBuffer,
                     0x18u,
                     0i64,
                     0);
          if ( Status < 0 )
            RtlNtStatusToDosError(Status);
        }
        result = Avast::Memory::GetDataByIndex(&dword_180010B70, &DataByIndex);
        if ( result >= 0 )
        {
          result = DataByIndex;
          if ( DataByIndex )
          {
            if ( *DataByIndex )
              *DataByIndex = 0;
          }
        }
      }
    }
  }
  return result;
}

__int64 __fastcall Avast__Hook__SetWindowsHookExA(
        __int64 HookId,
        LPVOID lpHookFunction,
        HINSTANCE hMod,
        unsigned int ThreadId)
{
  unsigned int Hook; 

  Hook = HookId;
  Avast::Hook::SetWindowsHookExInternal(HookId, ThreadId, lpHookFunction, 1);
  return oSetWindowsHookExA(Hook, lpHookFunction, hMod, ThreadId);
}

__int64 __fastcall Avast__Hook__SetWindowsHookExWHook(
        unsigned int HookId,
        __int64 lpHookFunction,
        __int64 hMod,
        unsigned int ThreadId)
{
  Avast::Hook::SetWindowsHookExInternal(HookId, ThreadId, lpHookFunction, 0);
  return oSetWindowsHookExW(HookId, lpHookFunction, hMod, ThreadId);
}

__int64 __fastcall Avast::Hook::GetKeyState(unsigned int nVirtKey)
{
  sub_180004CC0(3);
  return oGetKeyState(nVirtKey);
}

__int64 __fastcall Avast::Hook::GetKeyboardState(PBYTE lpKeyState)
{
  sub_180004CC0(2);
  return oGetKeyboardState(lpKeyState);
}

__int64 __fastcall Avast::Hook::CreateWindowExA(
        unsigned int dwExStyle,
        __int64 a2,
        const char *lpClassName,
        unsigned int dwStyle)
{
  if ( lpClassName )
    sub_180009110(0xCu, lpClassName, 0);
  return oCreateWindowsExA(dwExStyle, a2, lpClassName, dwStyle);
}

__int64 __fastcall Avast::Hook::CreateWindowExW(
        unsigned int dwExStyle,
        __int64 a2,
        _WORD *lpClassName,
        unsigned int dwStyle)
{
  __int64 i; 
  __int64 v9; 
  _BYTE *DataByIndex; 

  if ( lpClassName )
  {
    i = -1i64;
    do
      ++i;
    while ( lpClassName[i] );
    if ( Avast::Memory::GetDataByIndex(&dword_180010B70, &DataByIndex) >= 0 && DataByIndex && *DataByIndex != 1 )
    {
      *DataByIndex = 1;
      if ( i )
        sub_1800070B0(v9, 12, 0, lpClassName, i);
      if ( Avast::Memory::GetDataByIndex(&dword_180010B70, &DataByIndex) >= 0 && DataByIndex && *DataByIndex )
        *DataByIndex = 0;
    }
  }
  return oCreateWindowsExW(dwExStyle, a2, lpClassName, dwStyle);
}

__int64 __fastcall Avast::Hook::GetAsyncKeyState(unsigned int vKey)
{
  sub_180004CC0(3);
  return oGetAsyncKeyState(vKey);
}

__int64 __fastcall Avast::Hook::CoCreateInstance(
        CLSID *rCLSID,
        __int64 pUnknwn,
        __int64 dwClsContext,
        IID *rIID,
        LPVOID pPV)
{
  __int64 result; 
  unsigned int v8; 

  result = oCoCreateInstance(rCLSID);
  v8 = result;
  if ( result < 0 )
    return result;
  if ( byte_180011179 )
  {
    if ( !byte_18001117A )
    {
LABEL_9:
      if ( *&rCLSID->Data1 == 0x4CFCA4E50F87369Fi64 && *rCLSID->Data4 == 0xDD724515E6733EBDui64 )
        Avast::Util::CallSpecificPPV(pPV, rIID);
      goto LABEL_12;
    }
    if ( byte_18001117C )
      return result;
  }
  else if ( Avast::Util::CheckCLSID(rCLSID) )
  {
    sub_1800059D0(pPV, rIID);
  }
  if ( !byte_18001117A )
    goto LABEL_9;
LABEL_12:
  if ( !byte_18001117C && *&rCLSID->Data1 == 0x11CEA2AB148BD52Ai64 && *rCLSID->Data4 == 0x3055300AA001FB1i64 )
    sub_180005B20(pPV, rIID);
  return v8;
}

__int64 __fastcall Avast::Hook::RtlDecompressBuffer(
        __int64 CompressionFormat,
        _WORD *UncompressedBuffer,
        __int64 UncompressedBufferSize,
        __int64 CompressedBuffer,
        int CompressedBufferSize,
        unsigned int *FinalUncompressedSize)
{
  int v7; 
  __int64 v8; 
  char v9; 
  PHANDLE v10; 
  void *v11; 
  int v12; 
  _BYTE *v14; 
  __int64 InputBuffer[2]; 
  struct _IO_STATUS_BLOCK IoStatusBlock;

  v7 = oRtlDecompressBuffer(CompressionFormat, UncompressedBuffer);
  if ( v7 >= 0 )
  {
    v8 = *FinalUncompressedSize;
    if ( v8 >= 2
      && *UncompressedBuffer == 0x5A4D
      && v8 < dword_180010050
      && Avast::Memory::GetDataByIndex(&dword_180010B70, &v14) >= 0
      && v14
      && *v14 != 1 )
    {
      *v14 = 1;
      if ( Avast::Memory::GetDataByIndex(&dword_180010B70, &v14) >= 0 )
      {
        if ( v14 )
        {
          v9 = v14[1];
          if ( v9 )
          {
            v10 = FileHandle;
            v14[1] = v9 - 1;
            InputBuffer[1] = UncompressedBuffer;
            InputBuffer[0] = v8;
            if ( Avast::CreateFile(v10) >= 0 )
            {
              v11 = *v10;
              IoStatusBlock = 0i64;
              v12 = ZwDeviceIoControlFile(
                      v11,
                      0i64,
                      0i64,
                      0i64,
                      &IoStatusBlock,
                      0x53606148u,
                      InputBuffer,
                      0x10u,
                      0i64,
                      0);
              if ( v12 < 0 )
                RtlNtStatusToDosError(v12);
            }
          }
        }
      }
      if ( Avast::Memory::GetDataByIndex(&dword_180010B70, &v14) >= 0 && v14 && *v14 )
        *v14 = 0;
    }
  }
  return v7;
}

__int64 __fastcall Avast::Hook::CreateServiceA(
        __int64 hSCManager,
        LPCSTR *lpServiceName,
        __int64 a3,
        unsigned int dwDesiredAccess)
{
  if ( lpServiceName )
    Avast::Util::CreateUnicodeString(0xAu, lpServiceName, dwDesiredAccess);
  return oCreateServiceA(hSCManager, lpServiceName, a3, dwDesiredAccess);
}

__int64 __fastcall Avast::Hook::CreateServiceW(
        __int64 hSCManager,
        LPCWSTR lpServiceName,
        LPCWSTR lpDisplayName,
        DWORD dwDesiredAccess,
        DWORD dwServiceType,
        DWORD dwStartType,
        DWORD dwErrorControl,
        LPCWSTR lpBinaryPathName,
        LPCWSTR lpLoadOrderGroup,
        LPDWORD lpdwTagId,
        LPCWSTR lpDependencies,
        LPCWSTR lpServiceStartName,
        LPCWSTR lpPassword)
{
  __int64 i; 
  __int128 ServiceName; 
  LPCWSTR v20; 
  __int64 v21; 

  if ( lpServiceName )
  {
    i = -1i64;
    do
      ++i;
    while ( lpServiceName[i] );
    v20 = lpServiceName;
    v21 = i;
    *&ServiceName = lpServiceName;
    *(&ServiceName + 1) = i;
    Avast::Util::SendUnicodeStr(0xAu, &ServiceName, dwDesiredAccess);
  }
  return oCreateServiceW(
           hSCManager,
           lpServiceName,
           lpDisplayName,
           dwDesiredAccess,
           dwServiceType,
           dwStartType,
           dwErrorControl,
           lpBinaryPathName,
           lpLoadOrderGroup,
           lpdwTagId,
           lpDependencies,
           lpServiceStartName,
           lpPassword);
}

__int64 Avast::Hook::LdrLoadDll()
{
  unsigned int Res;

  Res = oLdrLoadDll();
  Avast::Hook::LdrLoadDllInternal();
  return Res;
}

__int64 __fastcall Avast::Hook::LogonUserW(LPCWSTR lpszUsername, LPCWSTR lpszPassword)
{
  __int64 result;

  result = oLogonUserW(lpszUsername, lpszPassword);
  if ( !result )
  {
    Avast::Util::QueryInformationProcess();
    return 0i64;
  }
  return result;
}

__int64 __fastcall Avast::Hook::OpenServiceA(__int64 hSCManager, const char *lpServiceName, int dwDesiredAccess)
{
  if ( lpServiceName )
    Avast::Util::CreateUnicodeString(0x8000000A, lpServiceName, dwDesiredAccess);
  return oOpenServiceA(hSCManager, lpServiceName, dwDesiredAccess);
}

__int64 __fastcall Avast::Hook::OpenServiceW(__int64 hSCManager, __int64 lpServiceName, int dwDesiredAccess)
{
  __int64 i;
  __int128 ServiceName; 
  __int64 v9;
  __int64 v10; 

  if ( lpServiceName )
  {
    i = -1i64;
    do
      ++i;
    while ( *(lpServiceName + 2 * i) );
    v9 = lpServiceName;
    v10 = i;
    *&ServiceName = lpServiceName;
    *(&ServiceName + 1) = i;
    Avast::Util::SendUnicodeStr(0x8000000A, &ServiceName, dwDesiredAccess);
  }
  return oOpenServiceW(hSCManager, lpServiceName, dwDesiredAccess);
}

