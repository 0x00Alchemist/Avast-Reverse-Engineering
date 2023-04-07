void __fastcall Notify::GetSpecificImageInfo(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
  PEPROCESS CurrentProcess; 
  unsigned __int16 i; 
  PWSTR Buffer; 
  WCHAR *v6;
  unsigned __int16 v7; 
  unsigned int k; 
  _BYTE *j;
  const UNICODE_STRING *String1; 
  __int64 v12; 
  UNICODE_STRING String2; 

  if ( HvGlobalState->gap1F0[0x1B8] )
  {
    if ( !HvGlobalState->gap1F0[441] )
    {
      CurrentProcess = IoGetCurrentProcess();
      if ( PsGetProcessWin32Process(CurrentProcess) )
        sub_14001D7B4(0);
    }
  }
  if ( HvGlobalState->byte4F2 && FullImageName && ImageInfo && (ImageInfo->Properties & 0x100) != 0 )
  {
    for ( i = FullImageName->Length >> 1; i; --i )
    {
      if ( FullImageName->Buffer[i - 1] == 92 )
        break;
    }
    Buffer = FullImageName->Buffer;
    String2.MaximumLength = FullImageName->Length - 2 * i;
    String2.Length = String2.MaximumLength;
    v6 = &Buffer[i];
    v7 = 0;
    String2.Buffer = v6;
    if ( String2.MaximumLength >> 1 )
    {
      while ( v6[v7] != 46 )
      {
        if ( ++v7 >= (String2.MaximumLength >> 1) )
          goto LABEL_17;
      }
      String2.Length = 2 * v7;
    }
LABEL_17:
    k = 0;
    for ( j = &unk_1400313F8; ; j += 48 )
    {
      if ( (*(j - 1) & 0x200) != 0 )
      {
        String1 = &VpcVmm + 3 * k;
        if ( *j ? RtlEqualUnicodeString(String1, &String2, 1u) : RtlPrefixUnicodeString(String1, &String2, 1u) )
          break;
      }
      if ( ++k >= 23 )
        return;
    }
    v12 = 6i64 * k;
    *(&VpcVmm + v12 + 4) = ImageInfo->ImageBase;
    *(&VpcVmm + v12 + 5) = ImageInfo->ImageSize;
  }
}
