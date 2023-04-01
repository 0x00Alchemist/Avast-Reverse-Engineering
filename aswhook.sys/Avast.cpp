__int64 __fastcall Avast::CreateFile(_WORD *handlePtr)
{
  char *filenamePointer;
  bool isNull;
  __int64 counter1;
  __int16 wordValue;
  __int64 errCodeHolder1;
  __int64 counter2;
  __int64 iterationCounter3;
  ACCESS_MASK accessMode;
  ACCESS_MASK acessMode2;
  char *charPtr;
  __int64 int64Var;
  __int16 int16Var;
  __int16 int16Var2;
  int ntStatusResult;
  ULONG dosErrorResult;
  __int16 v18;
  __int16 v19;
  __int128 *v20;
  __int128 v21;
  __int64 v22;
  struct _OBJECT_ATTRIBUTES objectAttributes; 
  struct _IO_STATUS_BLOCK ioStatusBlock;

  if ( *handlePtr != -1 )
    return 0;
  WORD4(v21) = 0;
  filenamePointer = &v20 + 6;
  *&v21 = 0x5C003F003F005C;
  do
  {
    isNull = *(filenamePointer + 1) == 0;
    filenamePointer += 2;
  }
  while ( !isNull );
  counter1 = 0;
  do
  {
    wordValue = handlePtr[counter1 + 5];
    *&filenamePointer[2 * counter1++] = wordValue;
  }
  while ( wordValue );
  errCodeHolder1 = -1;
  v20 = &v21;
  counter2 = -1;
  do
    ++counter2;
  while ( *(&v21 + counter2) );
  iterationCounter3 = 0;
  objectAttributes.Length = 48;
  isNull = *(handlePtr + 8) == 0;
  accessMode = 0x80100000;
  v19 = 2 * counter2;
  acessMode2 = 0x80100000;
  v18 = 2 * counter2;
  if ( !isNull )
    acessMode2 = 0xC0100000;
  objectAttributes.RootDirectory = 0;
  objectAttributes.Attributes = 64;
  objectAttributes.ObjectName = &v18;
  *&objectAttributes.SecurityDescriptor = 0;
  if ( ZwCreateFile(handlePtr, acessMode2, &objectAttributes, &ioStatusBlock, 0, 0x80u, 3u, 1u, 0x20u, 0, 0) >= 0 )
    return 0;
  charPtr = &v20 + 6;
  v21 = xmmword_180008710;
  v22 = 0x5C006C0061;
  do
  {
    isNull = *(charPtr + 1) == 0;
    charPtr += 2;
  }
  while ( !isNull );
  int64Var = 0;
  do
  {
    int16Var = handlePtr[int64Var + 5];
    *&charPtr[2 * int64Var++] = int16Var;
  }
  while ( int16Var );
  v20 = &v21;
  do
    ++errCodeHolder1;
  while ( *(&v21 + errCodeHolder1) );
  int16Var2 = 2 * errCodeHolder1;
  if ( *(handlePtr + 8) )
    accessMode = 0xC0100000;
  v19 = int16Var2;
  v18 = int16Var2;
  ntStatusResult = ZwCreateFile(
                     handlePtr,
                     accessMode,
                     &objectAttributes,
                     &ioStatusBlock,
                     0,
                     0x80u,
                     3u,
                     1u,
                     0x20u,
                     0,
                     0);
  if ( ntStatusResult >= 0 )
    return 0;
  dosErrorResult = RtlNtStatusToDosError(ntStatusResult);
  while ( dword_180008190[2 * iterationCounter3] != dosErrorResult )
  {
    if ( ++iterationCounter3 >= 0x21 )
      return dosErrorResult | 0xC0070000;
  }
  return LOWORD(dword_180008190[2 * iterationCounter3 + 1]) | 0xE0010000;
}

__int64 Avast::ProcessDataAndAddHandler()
{
  _QWORD *ptrDataStart;
  __int64 numChunksToProcess;

  ptrDataStart = &unk_18000B018;
  numChunksToProcess = 10;
  do
  {
    Avast::ProcessArray(ptrDataStart);
    ptrDataStart += 3;
    --numChunksToProcess;
  }
  while ( numChunksToProcess );
  dword_18000B108 = 0;
  return Avast::AddHandler(Avast::Util::ComputeValuesFromArray);
}

__int64 __fastcall Avast::ProcessExecuteData(
        _DWORD *input_buffer_one,
        __int64 input_two,
        _BYTE *processed_data_one,
        _BYTE *processed_data_two)
{
  char *funcptr;
  char tempValOne;
  unsigned __int8 *secondBufferPtr;
  _BYTE *tempValTwo;

  *processed_data_one = *processed_data_two;
  tempValOne = processed_data_two[1];
  secondBufferPtr = processed_data_two + 2;
  processed_data_one[1] = tempValOne;
  tempValTwo = processed_data_one + 2;
  input_buffer_one[3] = 1;
  funcptr = &unk_18000E150 + 16 * *secondBufferPtr;
  switch ( *(secondBufferPtr - 1) & 3 )
  {
    case 1:
      *input_buffer_one = 1;
      break;
    case 2:
      input_buffer_one[5] = 1;
      return (*(funcptr + 1))(input_buffer_one, funcptr, tempValTwo);
    case 3:
      input_buffer_one[4] = 1;
      return (*(funcptr + 1))(input_buffer_one, funcptr, tempValTwo);
  }
  return (*(funcptr + 1))(input_buffer_one, funcptr, tempValTwo);
}

__int64 __fastcall Avast::AddHandler(__int64 (*executableHandler)(void))
{
  int handlerIndex;

  if ( !executableHandler )
    return 0xFFFFFFFF;
  handlerIndex = index;
  if ( index >= 32 )
    return 0xFFFFFFFF;
  handlers[index] = executableHandler;
  index = handlerIndex + 1;
  return 0;
}

NTSTATUS __stdcall DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath)
{
  int check_1;
  int check_2;
  NTSTATUS operationStatus;

  if ( registryPath )
  {
    check_1 = registryPath - 1;
    if ( check_1 )
    {
      check_2 = check_1 - 1;
      if ( check_2 )
      {
        if ( check_2 == 1 )
          return Avast::IoDeviceOperation(driverObject, 3);
        else
          return 1;
      }
      else
      {
        return Avast::IoDeviceOperation(driverObject, 2);
      }
    }
    else
    {
      Avast::InitVariables();
      return Avast::IoDeviceOperation(driverObject, 1);
    }
  }
  else
  {
    operationStatus = Avast::IoDeviceOperation(driverObject, 0);
    Avast::ExecuteHandlers();
    return operationStatus;
  }
}