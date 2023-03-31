_BYTE *__fastcall Avast::Assembler::GetJumpTargetAddress(_BYTE *srcAddr)
{
  _BYTE *destAddr;
  __int64 jmpOffset;
  __int64 jmpTable;

  destAddr = srcAddr;
  if ( !srcAddr )
    return 0i64;
  if ( *srcAddr == 0xFF && srcAddr[1] == 0x25 )
  {
    jmpOffset = *(srcAddr + 2);
    if ( Avast::Memory::IsAddressMappedRange(srcAddr, &srcAddr[jmpOffset + 6]) )
      destAddr = *&destAddr[jmpOffset + 6];
  }
  if ( *destAddr == 0xEB )
  {
    destAddr += destAddr[1] + 2;
    if ( *destAddr == 0xFF )
    {
      if ( destAddr[1] == 0x25 )
      {
        jmpTable = *(destAddr + 2);
        if ( Avast::Memory::IsAddressMappedRange(destAddr, &destAddr[jmpTable + 6]) )
          return *&destAddr[jmpTable + 6];
      }
    }
    else if ( *destAddr == 0xE9 )
    {
      destAddr += *(destAddr + 1) + 5;
    }
  }
  return destAddr;
}

__int64 __fastcall Avast::Assembler::UpdateRegisters(
        _DWORD *registers,
        __int64 memoryLocation,
        _BYTE *inputInstruction,
        _BYTE *outputInstruction)
{
  char *_instructionTablePointer;
  _BYTE *_outputDestinationPointer;
  unsigned int _byte2DataValue;
  unsigned __int8 *_instructionSubBytesPointer;
  char _byte1DataValue;

  *inputInstruction = *outputInstruction;
  inputInstruction[1] = outputInstruction[1];
  inputInstruction[2] = outputInstruction[2];
  _outputDestinationPointer = inputInstruction + 3;
  _byte2DataValue = outputInstruction[2];
  _instructionSubBytesPointer = outputInstruction + 3;
  registers[2] |= _byte2DataValue >> 7;
  _byte1DataValue = outputInstruction[1] & 0x1F;
  registers[3] = 1;
  switch ( _byte1DataValue )
  {
    case 1:
      _instructionTablePointer = &unk_18000E150 + 16 * *_instructionSubBytesPointer;
      break;
    case 2:
      _instructionTablePointer = &unk_18000F190;
      break;
    case 3:
      _instructionTablePointer = &unk_18000F1B0;
      break;
    default:
      _instructionTablePointer = &unk_18000F180;
      break;
  }
  switch ( *(_instructionSubBytesPointer - 1) & 3 )
  {
    case 1:
      *registers = 1;
      break;
    case 2:
      registers[5] = 1;
      return (*(_instructionTablePointer + 1))(registers, _instructionTablePointer, _outputDestinationPointer);
    case 3:
      registers[4] = 1;
      return (*(_instructionTablePointer + 1))(registers, _instructionTablePointer, _outputDestinationPointer);
  }
  return (*(_instructionTablePointer + 1))(registers, _instructionTablePointer, _outputDestinationPointer);
}