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
              sub_180007250(v15, 0x80000006, DesiredAccess, v7, v6);
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
