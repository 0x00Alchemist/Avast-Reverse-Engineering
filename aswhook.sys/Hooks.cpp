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