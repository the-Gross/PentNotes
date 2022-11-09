unit hiRegProg;

interface

uses Windows,Kol,Share,Debug,MD5;

type TCodeLength = (key16,key32);

type
  TDebugProc = function: boolean; stdcall;
  
type
  ThiRegProg = class(TDebug)
   private
    fKeyCipher:string;
    ProgramID:string;
    fMaskActiv:string;
    fCodeLength:TCodeLength;
    fHashSum:boolean;
    fProgId:boolean;
    fNameFile:boolean;
    fIsDebug:boolean;
    FPathFName:string;
    function CheckRegistered:integer;
    function IsDebug:boolean;
    function GetActivate:string;
    function GetCipher:string;
   public

    _prop_Hidden:boolean;
    _data_Serial:THI_Event;
    _data_KeyActivate:THI_Event;
    _event_onRegistered:THI_Event;
    _event_onSerial:THI_Event;
    _event_onKeyActivate:THI_Event;
    _event_onControlReg:THI_Event;
    _event_onIsDebug:THI_Event;

    procedure _work_doControlReg(var _Data:TData; Index:word);
    procedure _work_doRegistered(var _Data:TData; Index:word);
    procedure _work_doSerial(var _Data:TData; Index:word);
    procedure _work_doKeyActivate(var _Data:TData; Index:word);
    procedure _work_doDeleteReg(var _Data:TData; Index:word);
    procedure _var_Registered(var _Data:TData; Index:word);

    property _prop_MaskActiv:string write fMaskActiv;
    property _prop_KeyCipher:string write fKeyCipher;
    property _prop_ProgramID:string write ProgramID;
    property _prop_CodeLength:TCodeLength write fCodeLength;    
    property _prop_HashSum:boolean write fHashSum;
    property _prop_ProgId:boolean write fProgId;
    property _prop_NameFile:boolean write fNameFile;    
    property _prop_IsDebug:boolean write fIsDebug;
    property _prop_PathFName:string write FPathFName;
        
    procedure _work_doProgramID(var _Data:TData; Index:word);
    procedure _work_doPathFName(var _Data:TData; Index:word);
    procedure _work_doMaskActiv(var _Data:TData; Index:word);    
    procedure _work_doKeyCipher(var _Data:TData; Index:word);      
  end;

implementation

uses hiCharset;

procedure ThiRegProg._work_doControlReg;
begin
   if fIsDebug and IsDebug then
      _hi_CreateEvent(_Data, @_event_onIsDebug)
   else   
      _hi_CreateEvent(_Data, @_event_onControlReg, CheckRegistered);
end;

function ThiRegProg.isDebug;
var   Kernel32: HMODULE;
      DebugProc: TDebugProc;
      isDebug: Boolean;
begin
   Kernel32 := GetModuleHandle('kernel32.dll');
   isDebug := (Kernel32 <> 0);
   if isDebug then begin
      @DebugProc := GetProcAddress(Kernel32, 'IsDebuggerPresent');
      if Assigned(DebugProc) then isDebug := DebugProc;
  end;
  Result := IsDebug;
end;

function ThiRegProg.CheckRegistered;
var
  Ser,Ser1,Ser2,Ser3,FileName,Serial,RCode:string;
  lencode,i:integer;
  FList: PStrList;
begin
  Result := 0;
  Serial := MD5DigestToStr( MD5String(GetActivate + GetCipher));
  SetLength(Serial, (integer(fCodeLength) + 1) * 16);
  FileName := IncludeTrailingChar(FPathFName, '\') + ProgramID;  
  if FileExists(FileName) then
  begin
    FList := NewStrList;
    FList.LoadFromFile(FileName);
    RCode := FList.text;
    Replace(RCode, #13#10, '');
    lencode := length(RCode); 
    Ser3 := Copy(RCode, 1, lencode div 3);
    Ser1 := Copy(RCode, lencode div 3 + 1, lencode div 3);
    Ser2 := Copy(RCode, (lencode * 2) div 3 + 1, lencode div 3);
    SetLength(Ser, length(RCode));
    for i:=0 to lencode div 3 - 1 do Ser[i*3+1] := Ser1[i+1];
    for i:=0 to lencode div 3 - 1 do Ser[i*3+2] := Ser2[i+1];  
    for i:=0 to lencode div 3 - 1 do Ser[i*3+3] := Ser3[i+1];
    RCode := Base64_DeCode(Ser);
    FList.free;
    if Serial = RCode then Result := 1;
  end;
end;

procedure ThiRegProg._work_doRegistered;
var
  FileName:string;
  Ser1,Ser2, Ser3, Serial:string;
  lencode: integer;
  i:integer;
  FList: PStrList;
begin
  FileName := IncludeTrailingChar(FPathFName, '\') + ProgramID;  
  Serial := ReadString(_Data,_data_Serial);
  Replace(Serial,'-','');
  Replace(Serial,' ','');
  Ser2 := MD5DigestToStr( MD5String(GetActivate + GetCipher));
  SetLength(Ser2, (integer(fCodeLength) + 1) * 16);
  if Serial = Ser2 then
  begin
    Serial := Base64_Code(Serial);
    lencode := length(Serial);
    SetLength(Ser1,lencode div 3);
    SetLength(Ser2,lencode div 3);
    SetLength(Ser3,lencode div 3);
    for i:=0 to lencode div 3 - 1 do Ser1[i+1] := Serial[i*3+1];
    for i:=0 to lencode div 3 - 1 do Ser2[i+1] := Serial[i*3+2];       
    for i:=0 to lencode div 3 - 1 do Ser3[i+1] := Serial[i*3+3];
    Serial := Ser3 + Ser1 + Ser2;
    FList := NewStrList;
    FList.text := Serial;
    FList.SaveToFile(FileName);
    if _prop_Hidden then
      SetFileAttributes(PChar(FileName), FILE_ATTRIBUTE_HIDDEN);     
    FList.free;
    _hi_CreateEvent(_Data, @_event_onRegistered,1);
  end
  else
    _hi_CreateEvent(_Data, @_event_onRegistered,0);
end;

procedure ThiRegProg._work_doDeleteReg;
var
  FileName:string;
begin
  FileName := IncludeTrailingChar(FPathFName, '\') + ProgramID;
  if FileExists(FileName) then
    DeleteFile(PChar(FileName)); 
end;

procedure ThiRegProg._work_doSerial;
var
  Activate,Serial:string;
begin
  Activate := ReadString(_Data,_data_KeyActivate);
  Replace(Activate,'-','');
  Replace(Activate,' ','');
  Serial := MD5DigestToStr( MD5String(Activate + GetCipher));
  SetLength(Serial, (integer(fCodeLength) + 1) * 16);
  _hi_CreateEvent(_Data, @_event_onSerial, Serial);
end;

procedure ThiRegProg._work_doKeyActivate;
begin
   _hi_CreateEvent(_Data, @_event_onKeyActivate, GetActivate);
end;

function ThiRegProg.GetActivate;
var   Reg:HKey;
      Key,BCode,Serial,Res,pfn,fn,pid:string;
begin
   if fNameFile then begin 
      SetLength(fn,1024);
      SetLength(fn,GetModuleFileName(HInstance,PChar(@fn[1]),1024));
      pfn := ExtractFileName(fn);
   end else
      pfn := '';   
   
   if fProgId then
      pid := ProgramID
   else
      pid := '';    

   if (FileExists(fn)) and fHashSum then
      Res := MD5DigestToStr( MD5File(fn))
   else
      Res :='';   

   key := 'SYSTEM\CurrentControlSet\Control\Biosinfo';
   Reg := RegKeyOpenRead(HKEY_LOCAL_MACHINE,Key);
   BCode := RegKeyGetStrEx(Reg,'SystemBiosDate'); 
   RegKeyClose(Reg);

   Serial := MD5DigestToStr( MD5String(BCode + Res));
   Serial := MD5DigestToStr( MD5String(pid + Serial));
   Serial := MD5DigestToStr( MD5String(pfn + Serial));
   SetLength(Serial, (integer(fCodeLength) + 1) * 16);
   Result := Serial;
end;

function ThiRegProg.GetCipher;
var   j,k:integer;
      str,s1,kstr,keystr:string;
      len:integer;
begin
   s1 := fMaskActiv;
   Replace(s1,'-','');
   Replace(s1,' ','');
   s1 := Copy(s1, 1, 16);
   len := length(s1) mod 16;
   if len <> 0 then
      len := ((length(s1) div 16)+1)*16
   else
      len := length(s1);
   SetLength(str, len);
   FillChar(str[1], len, '0');
   Move(s1[1], str[1], length(s1));
   kstr := fKeyCipher; 
   SetLength(keystr, len);
   FillChar(keystr[1], len, ' ');
   for j:= 1 to len do begin
      k := hex2int(str[j])+1;
      if k <= len then keystr[j] := kstr[k];
   end;
   Result := MD5DigestToStr( MD5String(keystr));
end;

procedure ThiRegProg._var_Registered;
begin
  dtInteger(_Data, CheckRegistered);
end;

procedure ThiRegProg._work_doProgramID;
begin
  ProgramID := ToString(_Data);
end;

procedure ThiRegProg._work_doPathFName;
begin
  FPathFName := ToString(_Data);
end;

procedure ThiRegProg._work_doMaskActiv;
begin
  fMaskActiv := ToString(_Data);
end;
    
procedure ThiRegProg._work_doKeyCipher;
begin
  fKeyCipher := ToString(_Data);
end;

end.