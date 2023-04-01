__int64 __fastcall Avast::Client::SendIoControlRequest(
        __int64 fileHandle,
        int controlCode,
        int accessFlag,
        const void *inputDataBuffer,
        __int64 inputDataLength)
{
  PHANDLE Handle;
  __int64 v8;
  size_t Len;
  __int64 result;
  _DWORD *heapPtr;
  void *InputBuffer;
  int fdResult;
  int statusResult;
  ULONG v15;
  struct _IO_STATUS_BLOCK IoStatusBlock;

  Handle = FileHandle;
  v8 = 0i64;
  Len = 2 * inputDataLength;
  result = 0xE0010002i64;
  if ( (2 * inputDataLength) < 0xFFFF )
    result = 0i64;
  if ( (2 * inputDataLength) < 0xFFFF )
  {
    heapPtr = Avast::Memory::AllocateHeap(Len + 12);
    InputBuffer = heapPtr;
    if ( heapPtr )
    {
      *heapPtr = controlCode;
      heapPtr[1] = accessFlag;
      heapPtr[2] = Len;
      memcpy(heapPtr + 3, inputDataBuffer, Len);
      fdResult = Avast::CreateFile(Handle);
      if ( fdResult >= 0 )
      {
        IoStatusBlock = 0i64;
        statusResult = ZwDeviceIoControlFile(
                         *Handle,
                         0i64,
                         0i64,
                         0i64,
                         &IoStatusBlock,
                         0x5360613Cu,
                         InputBuffer,
                         Len + 12,
                         0i64,
                         0);
        if ( statusResult >= 0 )
        {
          fdResult = 0;
        }
        else
        {
          v15 = RtlNtStatusToDosError(statusResult);
          while ( dword_18000D190[2 * v8] != v15 )
          {
            if ( ++v8 >= 0x21 )
            {
              fdResult = v15 | 0xC0070000;
              goto LABEL_14;
            }
          }
          fdResult = LOWORD(dword_18000D190[2 * v8 + 1]) | 0xE0010000;
        }
      }
LABEL_14:
      Avast::Memory::FreeHeap(InputBuffer);
      return fdResult;
    }
    else
    {
      return 0xE0010001i64;
    }
  }
  return result;
}

__int64 __fastcall Avast::Client::ReadData(__int64 outputBuffer, __int64 inputBuffer, _DWORD *resultBufferPointer)
{
  void **fileHandlePointer; // rdi
  __int64 result; // rax
  void *v6; // rcx
  int v7; // eax
  ULONG v8; // edx
  __int64 v9; // rax
  bool v10; // cf
  struct _IO_STATUS_BLOCK IoStatusBlock; // [rsp+50h] [rbp-18h] BYREF
  __int64 OutputBuffer; // [rsp+70h] [rbp+8h] BYREF
  __int64 InputBuffer; // [rsp+78h] [rbp+10h] BYREF

  OutputBuffer = outputBuffer;
  fileHandlePointer = FileHandle;
  InputBuffer = inputBuffer;
  result = Avast::CreateFile(FileHandle);
  if ( result >= 0 )
  {
    v6 = *fileHandlePointer;
    IoStatusBlock = 0i64;
    v7 = ZwDeviceIoControlFile(v6, 0i64, 0i64, 0i64, &IoStatusBlock, 0x53606174u, &InputBuffer, 8u, &OutputBuffer, 4u);
    if ( v7 >= 0 )
    {
      result = 0i64;
      v10 = IoStatusBlock.Information < 4;
      *resultBufferPointer = 0;
      if ( !v10 )
        *resultBufferPointer = OutputBuffer;
    }
    else
    {
      v8 = RtlNtStatusToDosError(v7);
      v9 = 0i64;
      while ( dword_18000D190[2 * v9] != v8 )
      {
        if ( ++v9 >= 0x21 )
          return v8 | 0xC0070000;
      }
      return LOWORD(dword_18000D190[2 * v9 + 1]) | 0xE0010000;
    }
  }
  return result;
}

__int64 __fastcall Avast::Client::ProcessIoControl(
        __int64 FileHandle,
        __int64 ControlCode,
        __int64 InputArgument1,
        const void *InputArgument2,
        unsigned __int64 OutputBufferSize,
        int *OutputBufferData)
{
  PHANDLE v6; 
  unsigned int v7; 
  __int64 result; 
  int v9; 
  ULONG v10; 
  __int64 v11;
  ULONG_PTR Information; 
  int *v13;
  int v14;
  struct _IO_STATUS_BLOCK IoStatusBlock;
  __int64 InputBuffer[4];
  unsigned int v17;
  int v18;
  __int64 v19;
  ULONG_PTR v20;

  HIDWORD(v20) = HIDWORD(FileHandle);
  v6 = ::FileHandle;
  v7 = OutputBufferSize;
  if ( OutputBufferSize > 8 )
    v7 = 8;
  LODWORD(v20) = v7;
  InputBuffer[0] = ControlCode;
  InputBuffer[1] = InputArgument1;
  InputBuffer[2] = InputArgument2;
  InputBuffer[3] = OutputBufferSize;
  v17 = v7;
  v18 = 0;
  if ( v7 )
    memcpy(&v19, InputArgument2, v7);
  result = Avast::CreateFile(v6);
  if ( result >= 0 )
  {
    IoStatusBlock = 0i64;
    v9 = ZwDeviceIoControlFile(
           *v6,
           0i64,
           0i64,
           0i64,
           &IoStatusBlock,
           0x53606128u,
           InputBuffer,
           v7 + 40,
           &OutputBufferSize,
           4u);
    if ( v9 >= 0 )
    {
      Information = IoStatusBlock.Information;
      result = 0i64;
      goto LABEL_15;
    }
    v10 = RtlNtStatusToDosError(v9);
    v11 = 0i64;
    while ( dword_18000D190[2 * v11] != v10 )
    {
      if ( ++v11 >= 0x21 )
      {
        result = v10 | 0xC0070000;
        goto LABEL_12;
      }
    }
    result = LOWORD(dword_18000D190[2 * v11 + 1]) | 0xE0010000;
LABEL_12:
    if ( result >= 0 )
    {
      Information = v20;
LABEL_15:
      v13 = OutputBufferData;
      *OutputBufferData = 0;
      v14 = *v13;
      if ( Information >= 4 )
        v14 = OutputBufferSize;
      *v13 = v14;
    }
  }
  return result;
}