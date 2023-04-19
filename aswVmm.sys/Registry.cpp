__int64 __fastcall Registry::CreateKey(
        void *RootDir,
        struct _UNICODE_STRING *ObjName,
        ACCESS_MASK DesiredAccess,
        ULONG CreateOptions,
        void *SecDesc,
        ULONG *Disp,
        _QWORD *hKey)
{
  NTSTATUS Status; 
  void *v8; 
  ULONG v9; 
  struct _OBJECT_ATTRIBUTES ObjectAttributes; 
  ULONG Disposition; 
  void *KeyHandle; 

  *(&ObjectAttributes.Attributes + 1) = 0;
  Disposition = 0;
  KeyHandle = 0i64;
  ObjectAttributes.SecurityQualityOfService = 0i64;
  ObjectAttributes.SecurityDescriptor = SecDesc;
  ObjectAttributes.RootDirectory = RootDir;
  ObjectAttributes.ObjectName = ObjName;
  *&ObjectAttributes.Length = 48i64;
  ObjectAttributes.Attributes = 576;
  Status = ZwCreateKey(&KeyHandle, DesiredAccess, &ObjectAttributes, 0, 0i64, CreateOptions, &Disposition);
  if ( Status >= 0 )
  {
    v9 = Disposition;
    v8 = KeyHandle;
  }
  else
  {
    v8 = 0i64;
    v9 = 0;
  }
  *hKey = v8;
  if ( Disp )
    *Disp = v9;
  return Status;
}

__int64 __fastcall Registry::CreateKeyWrapper(
        void *RootDir,
        WCHAR *KeyName,
        ACCESS_MASK DesiredAccess,
        ULONG CreateOptions,
        void *SecDesc,
        ULONG *Disposition,
        _QWORD *hKey)
{
  __int64 result; 
  _UNICODE_STRING ObjName; 

  ObjName = 0i64;
  result = Util::WcharToUnicode(&ObjName, KeyName);
  if ( result >= 0 )
    return Registry::CreateKey(RootDir, &ObjName, DesiredAccess, CreateOptions, SecDesc, Disposition, hKey);
  return result;
}

NTSTATUS __fastcall Registry::OpenKey(
        void *RootDir,
        struct _UNICODE_STRING *ObjName,
        ACCESS_MASK DesiredAccess,
        void **hKey)
{
  NTSTATUS result; 
  struct _OBJECT_ATTRIBUTES ObjectAttributes; 
  void *KeyHandle; 

  *(&ObjectAttributes.Attributes + 1) = 0;
  KeyHandle = 0i64;
  *hKey = 0i64;
  ObjectAttributes.RootDirectory = RootDir;
  ObjectAttributes.ObjectName = ObjName;
  *&ObjectAttributes.Length = 48i64;
  ObjectAttributes.Attributes = 0x240;
  *&ObjectAttributes.SecurityDescriptor = 0i64;
  result = ZwOpenKey(&KeyHandle, DesiredAccess, &ObjectAttributes);
  if ( result >= 0 )
    *hKey = KeyHandle;
  return result;
}

__int64 __fastcall Registry::OpenKeyWrapper(__int64 RootDir, __int64 Name, unsigned int DesiredAccess, __int64 hKey)
{
  __int64 result; 
  __int128 ObjName; 

  ObjName = 0i64;
  result = Util::WcharToUnicode(&ObjName);
  if ( result >= 0 )
    return Registry::OpenKey(RootDir, &ObjName, DesiredAccess, hKey);
  return result;
}

__int64 __fastcall Registry::QueryValueKeyFullInfo(
        HANDLE KeyHandle,
        PUNICODE_STRING ValueName,
        int a3,
        int a4,
        _QWORD *a5)
{
  _QWORD *v6; 
  unsigned int v9; 
  ULONG Length; 
  __int64 PoolWithTag; 
  NTSTATUS Status; 
  _DWORD *Pool; 
  ULONG ResultLength; 

  ResultLength = 0;
  v6 = a5;
  *a5 = 0i64;
  v9 = (ValueName->Length + 31) & 0xFFFFFFF8;
  Length = v9 + a4;
  if ( v9 + a4 < v9 )
    return 0xC0000095i64;
  PoolWithTag = ExAllocatePoolWithTag(512, Length, 'bRpP');
  if ( !PoolWithTag )
    return 0xC000009Ai64;
  Status = ZwQueryValueKey(KeyHandle, ValueName, KeyValueFullInformation, PoolWithTag, Length, &ResultLength);
  if ( Status < 0 )
  {
    ExFreePoolWithTag(PoolWithTag, 0);
    if ( Status != 0x80000005 && Status != 0xC0000023 )
      return Status;
    Pool = ExAllocatePoolWithTag(512, ResultLength, 'bRpP');
    PoolWithTag = Pool;
    if ( Pool )
    {
      Status = ZwQueryValueKey(KeyHandle, ValueName, KeyValueFullInformation, Pool, ResultLength, &ResultLength);
      if ( Status < 0 )
      {
LABEL_12:
        ExFreePoolWithTag(PoolWithTag, 0);
        return Status;
      }
      goto LABEL_9;
    }
    return 0xC000009Ai64;
  }
LABEL_9:
  if ( a3 && *(PoolWithTag + 4) != a3 )
  {
    Status = 0xC0000024;
    goto LABEL_12;
  }
  *v6 = PoolWithTag;
  return 0i64;
}

__int64 __fastcall Registry::QueryValueKeyWrapper(HANDLE KeyHandle, __int64 Name, int a3, int a4, _QWORD *a5)
{
  __int64 result; 
  struct _UNICODE_STRING ValueName; 

  ValueName = 0i64;
  result = Util::WcharToUnicode(&ValueName, Name);
  if ( result >= 0 )
    return Registry::QueryValueKeyFullInfo(KeyHandle, &ValueName, a3, a4, a5);
  return result;
}

NTSTATUS __fastcall Registry::QueryValueKeyPartialInfo(
        void *KeyHandle,
        struct _UNICODE_STRING *ValueName,
        int a3,
        _DWORD *ReturnInfo)
{
  NTSTATUS result; 
  ULONG RetLen; 
  _DWORD Info[4]; 

  RetLen = 0;
  result = ZwQueryValueKey(KeyHandle, ValueName, KeyValuePartialInformation, Info, 0x10u, &RetLen);
  if ( result >= 0 )
  {
    if ( Info[1] == 4 )
      a3 = Info[3];
    else
      result = 0xC0000024;
  }
  *ReturnInfo = a3;
  return result;
}

NTSTATUS __fastcall Registry::QueryValueKeyWrapper2(void *KeyHandle, __int64 Name, int a3, _DWORD *ReturnInfo)
{
  NTSTATUS result; 
  struct _UNICODE_STRING ValueName; 

  ValueName = 0i64;
  result = Util::WcharToUnicode(&ValueName, Name);
  if ( result >= 0 )
    return Registry::QueryValueKeyPartialInfo(KeyHandle, &ValueName, a3, ReturnInfo);
  return result;
}

__int64 __fastcall Registry::SetValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, unsigned __int16 *Data)
{
  unsigned __int64 v4; 
  int Status; 
  char *v8; 
  struct _UNICODE_STRING UnicodeString; 

  v4 = *Data;
  UnicodeString = 0i64;
  if ( Data[1] - v4 < 2 )
  {
    Status = Util::AllocateBuf(&UnicodeString, v4);
    if ( Status >= 0 )
    {
      v8 = *(Data + 1);
      UnicodeString.Length = *Data;
      sub_140029400(UnicodeString.Buffer, v8, UnicodeString.Length);
      UnicodeString.Buffer[UnicodeString.Length >> 1] = 0;
      Status = ZwSetValueKey(KeyHandle, ValueName, 0, 1u, UnicodeString.Buffer, UnicodeString.Length + 2);
      RtlFreeUnicodeString(&UnicodeString);
    }
  }
  else
  {
    *(*(Data + 1) + 2 * (v4 >> 1)) = 0;
    return ZwSetValueKey(KeyHandle, ValueName, 0, 1u, *(Data + 1), *Data + 2);
  }
  return Status;
}

__int64 __fastcall Registry::SetValueKeyWrapper(HANDLE KeyHandle)
{
  __int64 result; 
  __int128 Data; 
  struct _UNICODE_STRING ValueName; 

  ValueName = 0i64;
  Data = 0i64;
  result = Util::WcharToUnicode(&Data);
  if ( result >= 0 )
  {
    result = Util::WcharToUnicode(&ValueName);
    if ( result >= 0 )
      return Registry::SetValueKey(KeyHandle, &ValueName, &Data);
  }
  return result;
}

__int64 __fastcall Registry::SetValueKeyWrapper2(HANDLE KeyHandle, __int64 a2, unsigned __int16 *Data)
{
  __int64 result; 
  struct _UNICODE_STRING ValueName; 

  ValueName = 0i64;
  result = Util::WcharToUnicode(&ValueName);
  if ( result >= 0 )
    return Registry::SetValueKey(KeyHandle, &ValueName, Data);
  return result;
}

NTSTATUS __fastcall Registry::SetValueKeyWrapper3(HANDLE KeyHandle, __int64 a2, ULONG Type, void *Data, ULONG DataSize)
{
  NTSTATUS result; 
  struct _UNICODE_STRING ValueName; 

  ValueName = 0i64;
  result = Util::WcharToUnicode(&ValueName);
  if ( result >= 0 )
    return ZwSetValueKey(KeyHandle, &ValueName, 0, Type, Data, DataSize);
  return result;
}
