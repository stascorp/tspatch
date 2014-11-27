{
  Copyright 2012 Stas'M Corp.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
}

unit MainUnit;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, TLHelp32, StdCtrls, ExtCtrls, WinSvc, Registry, pngimage;

type
  TMemo = class(StdCtrls.TMemo)
  protected
    procedure WMPaint(var Message: TWMPaint); message WM_PAINT;
  end;
  TTSPatcher = class(TForm)
    Log: TMemo;
    MainPanel: TPanel;
    cConcur: TCheckBox;
    cHome: TCheckBox;
    cBlank: TCheckBox;
    cVPN: TCheckBox;
    bApply: TButton;
    bClose: TButton;
    cDriver: TCheckBox;
    cEnableTS: TCheckBox;
    cSingle: TCheckBox;
    Evnt: TTimer;
    procedure FormCreate(Sender: TObject);
    procedure bCloseClick(Sender: TObject);
    procedure cHomeClick(Sender: TObject);
    procedure LogChange(Sender: TObject);
    procedure LogGesture(Sender: TObject; const EventInfo: TGestureEventInfo;
      var Handled: Boolean);
    procedure LogKeyDown(Sender: TObject; var Key: Word; Shift: TShiftState);
    procedure LogKeyPress(Sender: TObject; var Key: Char);
    procedure LogMouseActivate(Sender: TObject; Button: TMouseButton;
      Shift: TShiftState; X, Y, HitTest: Integer;
      var MouseActivate: TMouseActivate);
    procedure LogMouseDown(Sender: TObject; Button: TMouseButton;
      Shift: TShiftState; X, Y: Integer);
    procedure LogMouseMove(Sender: TObject; Shift: TShiftState; X, Y: Integer);
    procedure FormDestroy(Sender: TObject);
    procedure bApplyClick(Sender: TObject);
    procedure FormActivate(Sender: TObject);
    procedure EvntTimer(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;
  TPatchThr = class(TThread)
  public
    Status: Cardinal;
    procedure Execute; override;
  end;
  IntArray = Array of Integer;
  //Record defined for use as return buffer
  _SERVICE_STATUS_PROCESS = record
    dwServiceType: DWORD;
    dwCurrentState: DWORD;
    dwControlsAccepted: DWORD;
    dwWin32ExitCode: DWORD;
    dwServiceSpecificExitCode: DWORD;
    dwCheckPoint: DWORD;
    dwWaitHint: DWORD;
    dwProcessId: DWORD;
    dwServiceFlags: DWORD;
  end;
  //Function Prototype
  function QueryServiceStatusEx(
  SC_HANDLE: SC_Handle;
  SC_STATUS_TYPE: Cardinal;
  out lpBuffer: _SERVICE_STATUS_PROCESS;
  cbBufSize: DWORD;
  out pcbBytesNeeded: LPDWORD
  ): BOOL; stdcall;

function QueryServiceStatusEx; external advapi32 name 'QueryServiceStatusEx';

var
  TSPatcher: TTSPatcher;
  Init, SilentMode: Boolean;
  Step: Byte;
  PatchThr: TPatchThr;
  OSVer: Byte;
  M: TMemoryStream;
  TSPid, Off1, Off2, Off3: Cardinal;
  Val1, Val2: Byte;
  Val3: Word;
  Background: TBitmap;

implementation

{$R *.dfm}
{$R resource.res}

procedure WriteLog(S: String);
begin
  TSPatcher.Log.Lines.Add(S);
  if SilentMode then
  try
    TSPatcher.Log.Lines.SaveToFile(ExtractFilePath(Application.ExeName)+'TSPatch.log');
  except

  end;
end;

function GetDOSEnvVar(const VarName: string): string;
var
  i: integer;
begin
  Result := '';
  try
    i := GetEnvironmentVariable(PChar(VarName), nil, 0);
    if i > 0 then
      begin
        SetLength(Result, i);
        GetEnvironmentVariable(Pchar(VarName), PChar(Result), i);
      end;
    if Result[Length(Result)]=#0 then
      Delete(Result,Length(Result),1);
  except
    Result := '';
  end;
end;

function GetSystem: String;
begin
  Result:=GetDOSEnvVar('SystemRoot')+'\';
end;

function GetModuleAddress(ModuleName: String; ProcessId: Cardinal; var BaseAddr: Pointer; var BaseSize: DWord): Boolean;
var
  hSnap: THandle;
  md: MODULEENTRY32;
begin
  Result := False;
  hSnap := CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ProcessId);
  if hSnap = INVALID_HANDLE_VALUE Then
    Exit;
  md.dwSize := SizeOf(MODULEENTRY32);
  if Module32First(hSnap, md) then
  begin
    if LowerCase(ExtractFileName(md.szExePath)) = LowerCase(ModuleName) then
    begin
      Result := True;
      BaseAddr := Pointer(md.modBaseAddr);
      BaseSize := md.modBaseSize;
      CloseHandle(hSnap);
      Exit;
    end;
    while Module32Next(hSnap, md) Do
    begin
      if LowerCase(ExtractFileName(md.szExePath)) = LowerCase(ModuleName) then
      begin
        Result := True;
        BaseAddr := Pointer(md.modBaseAddr);
        BaseSize := md.modBaseSize;
        Break;
      end;
    end;
  end;
  CloseHandle(hSnap);
end;

function ReadFirstLineMultiSz(const CurrentKey: HKey;
  const Subkey, ValueName: string): String;
var
  valueType: DWORD;
  valueLen: DWORD;
  p, buffer: PChar;
  Key: HKey;
  Strings: TStringList;
begin
  Result:='';
  Strings:=TStringList.Create;
  // open the specified key
  if RegOpenKeyEx(CurrentKey, PChar(Subkey), 0, KEY_READ, Key)
    = ERROR_SUCCESS then
  begin
    // retrieve the type and data for a specified value name
    SetLastError(RegQueryValueEx(Key, PChar(ValueName), nil, @valueType, nil,
        @valueLen));
    if GetLastError = ERROR_SUCCESS then
      if valueType = REG_MULTI_SZ then
      begin
        GetMem(buffer, valueLen);
        try
          // receive the value's data (in an array).
          RegQueryValueEx(Key, PChar(ValueName), nil, nil, PBYTE(buffer),
            @valueLen);
          // Add values to stringlist
          p := buffer;
          while p^ <> #0 do
          begin
            Strings.Add(p);
            Inc(p, lstrlen(p) + 1)
          end;
        finally
          FreeMem(buffer);
          if Strings.Count > 0 then
            Result:=Strings.Strings[0];
          Strings.Free;
        end;
      end
      else
        raise ERegistryException.Create('StringList expected')
      else
        raise ERegistryException.Create('Can not read REG_MULTI_SZ value');
  end;
end;

function Is64BitWindows: Boolean;
var
  IsWow64Process: function(hProcess: THandle; out Wow64Process: Bool): Bool; stdcall;
  Wow64Process: Bool;
begin
  {$IF Defined(CPU64)}
  Result := True; // 64-áèòíàÿ ïðîãðàììà çàïóñêàåòñÿ òîëüêî íà Win64
  {$ELSEIF Defined(CPU16)}
  Result := False; // Win64 íå ïîääåðæèâàåò 16-ðàçðÿäíûå ïðèëîæåíèÿ
  {$ELSE}
  // 32-áèòíûå ïðîãðàììû ìîãóò ðàáîòàòü è íà 32-ðàçðÿäíîé è íà 64-ðàçðÿäíîé Windows
  // òàê ÷òî ýòîò âîïðîñ òðåáóåò äàëüíåéøåãî èññëåäîâàíèÿ
  IsWow64Process := GetProcAddress(GetModuleHandle(Kernel32), 'IsWow64Process');

  Wow64Process := False;
  if Assigned(IsWow64Process) then
    Wow64Process := IsWow64Process(GetCurrentProcess, Wow64Process) and Wow64Process;

  Result := Wow64Process;
  {$IFEND}
end;

function ServiceQuery(Name: String): ShortInt;
var
  ssStatus: SERVICE_STATUS;
  schSCManager: SC_HANDLE;
  schService: SC_HANDLE;
  pcbBytesNeeded, lpServicesReturned, lpResumeHandle: DWORD;
begin
  schSCManager := OpenSCManager(nil, nil, GENERIC_READ);
  if schSCManager = 0 then begin
    Result:=-1;
    Exit;
  end;
  schService := OpenService(schSCManager, PChar(Name), MAXIMUM_ALLOWED);
  if schService = 0 then begin
    Result:=-1;
    Exit;
  end;
  if QueryServiceStatus(schService, ssStatus) then begin
    if (ssStatus.dwCurrentState = SERVICE_STOPPED) or
       (ssStatus.dwCurrentState = SERVICE_STOP_PENDING) then
      Result:=0;
    if (ssStatus.dwCurrentState = SERVICE_RUNNING) or
       (ssStatus.dwCurrentState = SERVICE_START_PENDING) then
      Result:=1;
  end;
end;

function ExecAppAndWait(ACommandLine,  AWorkDir: String): DWORD;
var
  R: Boolean;
  ProcessInformation: TProcessInformation;
  StartupInfo: TStartupInfo;
  ExCode: DWORD;
begin
  UniqueString(ACommandLine);
  UniqueString(AWorkDir);
  FillChar(StartupInfo, SizeOf(TStartupInfo), 0);
  with StartupInfo do
  begin
    cb := SizeOf(TStartupInfo);
    dwFlags := STARTF_USESHOWWINDOW;
    wShowWindow := SW_HIDE;
  end;
  R := CreateProcess(
    nil, // Pointer to name of executable module
    PChar(ACommandLine), // Pointer to command line string
    nil, // Pointer to process security attributes
    nil, // Pointer to thread security attributes
    False, // handle inheritance flag
    0, // creation flags
    nil, // Pointer to new environment block
    PChar(AWorkDir), // Pointer to current directory name
    StartupInfo, // Pointer to STARTUPINFO
    ProcessInformation); // Pointer to PROCESS_INFORMATION
  if R then begin
    WaitForSingleObject(ProcessInformation.hProcess, INFINITE);
    GetExitCodeProcess(ProcessInformation.hProcess, ExCode);
    if ExCode = STILL_ACTIVE then begin
      TerminateThread(ProcessInformation.hThread, 0);
      TerminateProcess(ProcessInformation.hProcess, 0);
    end;
    Result:=ExCode;
    CloseHandle(ProcessInformation.hThread);
    CloseHandle(ProcessInformation.hProcess);
  end else
    Result := GetLastError;
end;

procedure TTSPatcher.bCloseClick(Sender: TObject);
begin
  Close;
end;

function GetServicePid(sService: String; sMachine: String = ''): Cardinal;
var
  schm,
  schs: SC_Handle;
  SC_STATUS_TYPE: Cardinal;
  lpBuffer: _SERVICE_STATUS_PROCESS;
  cbBufSize: DWORD;
  pcbBytesNeeded: LPDWORD;
begin
  //open the service manager  (defined in WinSvc)
  schm := OpenSCManager(PChar(sMachine), nil, SC_MANAGER_CONNECT);
  //set the status type to SC_STATUS_PROCESS_INFO
  //this is currently the only value supported
  SC_STATUS_TYPE := $00000000;
  //set the buffer size to the size of the record
  cbBufSize := sizeof(_SERVICE_STATUS_PROCESS);
  if (schm>0) then
  begin
    //grab the service handle
    schs := OpenService(schm, PChar(sService), SERVICE_QUERY_STATUS);
    if (schs>0) then
    begin
      //call the function
      QueryServiceStatusEx(
      schs,
      SC_STATUS_TYPE,
      lpBuffer,
      cbBufSize,
      pcbBytesNeeded);
      CloseServiceHandle(schs);
    end;
    CloseServiceHandle(schm);
  end;
  Result := lpBuffer.dwProcessId;
end;

function AddPrivilege(SePriv: String): Boolean;
var
  hToken: THandle;
  SeNameValue: Int64;
  tkp: TOKEN_PRIVILEGES;
  ReturnLength: Cardinal;
  E: Cardinal;
begin
  Result:=False;
  if not OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES
  or TOKEN_QUERY, hToken) then begin
    E:=GetLastError;
    WriteLog('[-] Unable to get '+SePriv+' (Error code: '+IntToStr(E)+','+SysErrorMessage(E)+')');
    Exit;
  end;
  if not LookupPrivilegeValue(nil, PWideChar(SePriv), SeNameValue) then begin
    E:=GetLastError;
    WriteLog('[-] Unable to get '+SePriv+' (Error code: '+IntToStr(E)+','+SysErrorMessage(E)+')');
    CloseHandle(hToken);
    Exit;
  end;
  tkp.PrivilegeCount:=1;
  tkp.Privileges[0].Luid := SeNameValue;
  tkp.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED;
  AdjustTokenPrivileges(hToken, False, tkp, SizeOf(tkp), tkp, ReturnLength);
  if GetLastError()<>ERROR_SUCCESS then begin
    E:=GetLastError;
    WriteLog('[-] Unable to get '+SePriv+' (Error code: '+IntToStr(E)+','+SysErrorMessage(E)+')');
    Exit;
  end;
  Result:=True;
end;

procedure FindInMemStream(Stream: TMemoryStream; Buf: Pointer; Size: DWord;
  From: Cardinal; var A: IntArray);
var
  Buf1: Pointer;
  I: Integer;
  strSz: Int64;
begin
  SetLength(A, 0);
  strSz:=Stream.Size;
  Buf1:=Stream.Memory;
  I:=From;
  if From>0 then
    Inc(PByte(Buf1), From);
  while I < strSz - Size + 1 do begin
    if CompareMem(Buf1, Buf, Size) then begin
      SetLength(A, Length(A)+1);
      A[Length(A)-1] := I;
    end;
    Inc(I);
    Inc(PByte(Buf1));
    //Pr:=Round((I-From)*(1000/(Sz-Len+1-From)));
  end;
end;

procedure TTSPatcher.cHomeClick(Sender: TObject);
begin
  cDriver.Visible := cHome.Checked;
end;

procedure CreateArray(var Arr: Array of Byte; const A: Array of Byte);
var I: Integer;
begin
  for I:=Low(A) to High(A) do
    Arr[I] := A[I];
end;

function SearchSignatures: Boolean;
var
  b11: Array[0..6] of Byte;
  b21: Array[0..3] of Byte;
  b22: Array[0..4] of Byte;
  b31: Array[0..2] of Byte;
  b32: Array[0..2] of Byte;
  b1,b2: Boolean;
  A1,A2: IntArray;
  I,J: Integer;
begin
  Result:=False;
  CreateArray(b11, [$19,$3B,$C7,$75,$15,$89,$BB]);
  CreateArray(b21, [$83,$78,$24,$00]);
  CreateArray(b22, [$04,$33,$C0,$EB,$2C]);
  CreateArray(b31, [$3B,$46,$0C]);
  CreateArray(b32, [$8B,$45,$08]);

  FindInMemStream(M, @b11[0], Length(b11), $400, A1);
  if Length(A1)=0 then
    Exit;
  Off1:=A1[0]-1;

  FindInMemStream(M, @b21[0], Length(b21), Off1 + $1000, A1);
  if Length(A1)=0 then
    Exit;
  FindInMemStream(M, @b22[0], Length(b22), A1[0]+5, A2);
  if Length(A2)=0 then
    Exit;
  b1:=False;
  for I:=0 to Length(A1)-1 do begin
    for J:=0 to Length(A2)-1 do
      if A2[J]-A1[I] = 5 then begin
        b1:=True;
        Off2:=A1[I]+4;
      end;
    if b1 then
      Break;
  end;
  if not b1 then
    Exit;

  FindInMemStream(M, @b31[0], Length(b31), Off2 + $20, A1);
  if Length(A1)=0 then
    Exit;
  FindInMemStream(M, @b32[0], Length(b32), A1[0]+5, A2);
  if Length(A2)=0 then
    Exit;
  b1:=False;
  for I:=0 to Length(A1)-1 do begin
    for J:=0 to Length(A2)-1 do
      if A2[J]-A1[I] = 5 then begin
        b1:=True;
        Off3:=A1[I]+3;
      end;
    if b1 then
      Break;
  end;
  if not b1 then
    Exit;
  Result:=True;
end;

procedure ExtractRes(ResName,Path: String);
var
  ResStream: TResourceStream;
  MyFileStream: TFileStream;
begin
  try
    MyFileStream := TFileStream.Create(Path, fmCreate or fmShareExclusive);
    ResStream := TResourceStream.Create(HInstance, ResName, RT_RCDATA);
    MyFileStream.CopyFrom(ResStream, 0);
  finally
    MyFileStream.Free;
    ResStream.Free;
  end;
end;

procedure WFPKill(FN: String);
var
  func: Pointer;
  hmod, hlib: LongInt;
  fnamew: PWideChar;
  wideChars : array[0..1024] of WideChar;
begin
  fnamew:=StringToWideChar(FN, widechars, Length(FN)+1);
  hlib:=LoadLibrary(PChar(GetSystem+'system32\sfc_os.dll'));
  if hlib<>0 then begin
    func:=GetProcAddress(hlib, MAKEINTRESOURCE(5));
    asm
      push -1
      push fnamew
      push 0
      call func
    end;
  end;
end;

procedure TTSPatcher.EvntTimer(Sender: TObject);
var
  hProc: THandle;
  Base: Pointer;
  Sz, dw: DWord;
  ver: _OSVERSIONINFOEXW;
  E: Cardinal;
  R: TRegistry;
  b1,b2, ReadData: Boolean;
  ps, cs1, cs2: Boolean;
begin
  if Step = 0 then
    Step := 255
  else begin
    Evnt.Enabled:=False;
    Exit;
  end;

  R:=TRegistry.Create;
  R.RootKey := HKEY_LOCAL_MACHINE;

  AddPrivilege('SeDebugPrivilege');

  if R.OpenKey('SYSTEM\CurrentControlSet\Control\Terminal Server', False) then begin
    try
      TSPatcher.cEnableTS.Checked := not R.ReadBool('fDenyTSConnections');
    except

    end;
    try
      TSPatcher.cSingle.Checked := R.ReadBool('fSingleSessionPerUser');
    except
      TSPatcher.cSingle.Checked := True;
    end;
    R.CloseKey;
  end;
  if R.OpenKey('SYSTEM\CurrentControlSet\Control\Lsa', False) then begin
    try
      TSPatcher.cBlank.Checked := not R.ReadBool('limitblankpassworduse');
    except

    end;
    R.CloseKey;
  end;
  if R.OpenKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', False) then begin
    try
      TSPatcher.cVPN.Checked := R.ReadString('KeepRasConnections') = '1';
     except

    end;
    R.CloseKey;
  end;

  OSVer:=255;
  WriteLog('[*] Getting system info…');
  FillChar(ver, SizeOf(ver), 0);
  ver.dwOSVersionInfoSize := SizeOf(ver);
  GetVersionEx(ver);
  case ver.dwMajorVersion of
    4: WriteLog('[-] Windows NT 4.x is not supported.');
    5: case ver.dwMinorVersion of
      0: WriteLog('[-] Windows 2000 is not supported.');
      1: begin
        WriteLog('[+] Windows XP detected.');
        OSVer:=1;
      end;
      2: WriteLog('[-] Windows Server 2003 is not supported.');
    end;
    6: case ver.dwMinorVersion of
      0: WriteLog('[-] Windows Vista / Server 2008 is not supported.');
      1: WriteLog('[-] Windows 7 / Server 2008 R2 is not supported.');
      2: WriteLog('[-] Windows 8 is not supported.');
    end;
    else
      WriteLog('[-] Unknown Windows NT '+IntToStr(ver.dwMajorVersion)+'.'+
      IntToStr(ver.dwMinorVersion)+' kernel version.');
  end;
  ReadData:=False;
  if OSVer <> 1 then begin
    R.Free;
    Exit;
  end;
  if Is64BitWindows then begin
    R.Free;
    WriteLog('[-] Windows x64 platform not supported.');
    Exit;
  end;
  M:=TMemoryStream.Create;
  b1:=False;
  try
    M.SaveToFile(GetSystem+'TSPatch.txt');
  except
    b1:=True;
  end;
  M.Free;
  if b1 then begin
    R.Free;
    WriteLog('[-] Administrator privileges is required to patch.');
    Exit;
  end else
    DeleteFile(GetSystem+'TSPatch.txt');
  WriteLog('[*] Querying Terminal Services status…');
  TSPid:=0;
  case ServiceQuery('TermService') of
    -1: WriteLog('[-] Terminal Services not found.');
    0: WriteLog('[*] Terminal Services is stopped.');
    1: begin
      TSPid:=GetServicePid('TermService');
      WriteLog('[+] Terminal Services found (pid: '+IntToStr(TSPid)+').');
    end;
  end;
  if TSPid > 0 then begin
    WriteLog('[*] Looking for termsrv.dll module…');
    if GetModuleAddress('termsrv.dll', TSPid, Base, Sz) then begin
      hProc := OpenProcess(MAXIMUM_ALLOWED, False, TSPid);
      if hProc=0 then begin
        E:=GetLastError;
        WriteLog('[-] Can''t open process (Error code: '+IntToStr(E)+', '+SysErrorMessage(E)+')');
      end else begin
        M:=TMemoryStream.Create;
        M.SetSize(Sz);
        if not ReadProcessMemory(hProc, Base, M.Memory, Sz, dw) then begin
          CloseHandle(hProc);
          M.Free;
          E:=GetLastError;
          WriteLog('[-] Can''t read process memory (Error code: '+IntToStr(E)+', '+SysErrorMessage(E)+')');
        end else begin
          WriteLog('[+] Module termsrv.dll found!');
          WriteLog('[*] Module size: '+IntToStr(M.Size)+' bytes.');
          WriteLog('[*] Searching for signatures…');

          if not SearchSignatures then begin
            CloseHandle(hProc);
            M.Free;
            WriteLog('[-] Specific signature in termsrv.dll not found.');
          end else begin
            CloseHandle(hProc);
            WriteLog('[+] Required signatures found!');

            M.Seek(Off1, soFromBeginning);
            M.ReadBuffer(Val1, 1);
            M.Seek(Off2, soFromBeginning);
            M.ReadBuffer(Val2, 1);
            M.Seek(Off3, soFromBeginning);
            M.ReadBuffer(Val3, 2);
            M.Free;
            case Val1 of
              $74: ps:=False;
              $EB: ps:=True;
              else begin
                ps:=False;
                WriteLog('[-] ProductSuite check has unknown value.');
              end;
            end;
            case Val2 of
              $74: cs1:=False;
              $75: cs1:=True;
              else begin
                cs1:=False;
                WriteLog('[-] Concurrent sessions check 1 has unknown value.');
              end;
            end;
            case Val3 of
              $167F: cs2:=False;
              $9090: cs2:=True;
              else begin
                cs2:=False;
                WriteLog('[-] Concurrent sessions check 2 has unknown value.');
              end;
            end;
            ReadData:=True;
          end;
        end;
      end;
    end else
      WriteLog('[-] termsrv.dll library is not loaded.');
  end;
  WriteLog('[*] Reading termsrv.dll from system directory…');
  if not FileExists(GetSystem+'system32\termsrv.dll') then
    WriteLog('[-] termsrv.dll not found in system directory.')
  else begin
    M:=TMemoryStream.Create;
    M.LoadFromFile(GetSystem+'system32\termsrv.dll');
    WriteLog('[*] File size: '+IntToStr(M.Size)+' bytes.');
    WriteLog('[*] Searching for signatures…');
    if not SearchSignatures then
      WriteLog('[-] Specific signature in termsrv.dll not found.')
    else begin
      WriteLog('[+] Required signatures found!');
      M.Seek(Off1, soFromBeginning);
      M.ReadBuffer(Val1, 1);
      M.Seek(Off2, soFromBeginning);
      M.ReadBuffer(Val2, 1);
      M.Seek(Off3, soFromBeginning);
      M.ReadBuffer(Val3, 2);
      case Val1 of
        $74: ps:=False;
        $EB: ps:=True;
        else begin
          ps:=False;
          WriteLog('[-] ProductSuite check has unknown value.');
        end;
      end;
      case Val2 of
        $74: cs1:=False;
        $75: cs1:=True;
        else begin
          cs1:=False;
          WriteLog('[-] Concurrent sessions check 1 has unknown value.');
        end;
      end;
      case Val3 of
        $167F: cs2:=False;
        $9090: cs2:=True;
        else begin
          cs2:=False;
          WriteLog('[-] Concurrent sessions check 2 has unknown value.');
        end;
      end;
      ReadData:=True;
    end;
    M.Free;
  end;

  if ReadData then begin
    b1 := False; b2 := False;
    if R.OpenKey('SYSTEM\CurrentControlSet\Control\Terminal Server\Licensing Core', False) then begin
      try
        b1 := R.ReadBool('EnableConcurrentSessions');
      except

      end;
      R.CloseKey;
    end;
    if R.OpenKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', False) then begin
      try
        b2 := R.ReadBool('AllowMultipleTSSessions');
      except

      end;
      R.CloseKey;
    end;
    if b1 and b2 and cs1 and cs2 then
      TSPatcher.cConcur.Checked := True;
    if ps then begin
      TSPatcher.cHome.Checked := True;
      TSPatcher.cDriver.Visible := True;
    end;
    TSPatcher.bApply.Enabled:=True;
    TSPatcher.cEnableTS.Enabled:=True;
    TSPatcher.cConcur.Enabled:=True;
    TSPatcher.cBlank.Enabled:=True;
    TSPatcher.cVPN.Enabled:=True;
    TSPatcher.cSingle.Enabled:=True;
    TSPatcher.cHome.Enabled:=True;
    TSPatcher.cDriver.Enabled:=True;
    WriteLog('[*] Ready to patch.');
  end;
  R.Free;
end;

procedure RunPatch;
var
  R: TRegistry;
  hProc: THandle;
  Base: Pointer;
  Sz, dw: DWord;
  E: Cardinal;
  b1,b2: Boolean;
  ps1, ps2, cs: Boolean;
begin
  WriteLog('[*] Updating system configuration…');
  R:=TRegistry.Create;
  R.RootKey:=HKEY_LOCAL_MACHINE;
  if SilentMode then begin
    TSPatcher.cEnableTS.Checked := True;
    TSPatcher.cConcur.Checked := True;
    TSPatcher.cVPN.Checked := True;
    TSPatcher.cHome.Checked := True;
    if R.OpenKey('SYSTEM\CurrentControlSet\Control\ProductOptions', False) then begin
      b1:=False;
      b2:=False;
      try
        b1 := ReadFirstLineMultiSz(HKEY_LOCAL_MACHINE,
        'SYSTEM\CurrentControlSet\Control\ProductOptions',
        'ProductSuite') = 'Personal';
      except
        WriteLog('[-] Can''t detect Windows edition.');
      end;
      try
        b2 := R.ReadString('ProductType') = 'WinNT';
      except
        WriteLog('[-] Can''t detect Windows edition.');
      end;
      R.CloseKey;
    end;
    TSPatcher.cDriver.Checked := (b1 and b2);
  end;
  if TSPatcher.cEnableTS.Checked then begin
    WriteLog('[*] Enabling Remote Desktop…');
    if R.OpenKey('SYSTEM\CurrentControlSet\Control\Terminal Server', False) then begin
      try
        R.WriteBool('fDenyTSConnections', False);
      except
        WriteLog('[-] Can''t write to registry.');
      end;
      R.CloseKey;
    end;
    ExecAppAndWait('sc.exe config TermService start= auto', GetSystem+'system32');
    ExecAppAndWait('sc.exe start TermService', GetSystem+'system32');
    ExecAppAndWait('netsh.exe firewall set service type = remotedesktop mode = enable', GetSystem+'system32');
  end else begin
    WriteLog('[*] Disabling Remote Desktop…');
    if R.OpenKey('SYSTEM\CurrentControlSet\Control\Terminal Server', False) then begin
      try
        R.WriteBool('fDenyTSConnections', True);
      except
        WriteLog('[-] Can''t write to registry.');
      end;
      R.CloseKey;
    end;
    ExecAppAndWait('netsh.exe firewall set service type = remotedesktop mode = disable', GetSystem+'system32');
  end;
  if R.OpenKey('SYSTEM\CurrentControlSet\Control\Terminal Server\Licensing Core', False) then begin
    try
      R.WriteBool('EnableConcurrentSessions', TSPatcher.cEnableTS.Checked);
    except

    end;
    R.CloseKey;
  end;
  if R.OpenKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', False) then begin
    try
      R.WriteBool('AllowMultipleTSSessions', TSPatcher.cEnableTS.Checked);
    except

    end;
    R.CloseKey;
  end;
  if R.OpenKey('SYSTEM\CurrentControlSet\Control\Lsa', False) then begin
    try
      R.WriteBool('limitblankpassworduse', not TSPatcher.cBlank.Checked);
    except
      WriteLog('[-] Can''t write to registry.');
    end;
    R.CloseKey;
  end;
  if R.OpenKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', False) then begin
    try
      if TSPatcher.cVPN.Checked then
        R.WriteString('KeepRasConnections', '1')
      else
        R.WriteString('KeepRasConnections', '0');
    except
      WriteLog('[-] Can''t write to registry.');
    end;
    R.CloseKey;
  end;
  if R.OpenKey('SYSTEM\CurrentControlSet\Control\Terminal Server', False) then begin
    try
      R.WriteBool('fSingleSessionPerUser', TSPatcher.cSingle.Checked);
    except
      WriteLog('[-] Can''t write to registry.');
    end;
    R.CloseKey;
  end;

  WriteLog('[*] Querying Terminal Services status…');
  TSPid:=0;
  case ServiceQuery('TermService') of
    -1: WriteLog('[-] Terminal Services not found.');
    0: WriteLog('[*] Terminal Services is stopped.');
    1: begin
      TSPid:=GetServicePid('TermService');
      WriteLog('[+] Terminal Services found (pid: '+IntToStr(TSPid)+').');
    end;
  end;
  if TSPid > 0 then begin
    WriteLog('[*] Patching in realtime mode…');
    WriteLog('[*] Looking for termsrv.dll module…');
    if GetModuleAddress('termsrv.dll', TSPid, Base, Sz) then begin
      hProc := OpenProcess(MAXIMUM_ALLOWED, False, TSPid);
      if hProc=0 then begin
        E:=GetLastError;
        WriteLog('[-] Can''t open process (Error code: '+IntToStr(E)+', '+SysErrorMessage(E)+')');
      end else begin
        M:=TMemoryStream.Create;
        M.SetSize(Sz);
        if not ReadProcessMemory(hProc, Base, M.Memory, Sz, dw) then begin
          CloseHandle(hProc);
          M.Free;
          E:=GetLastError;
          WriteLog('[-] Can''t read process memory (Error code: '+IntToStr(E)+', '+SysErrorMessage(E)+')');
        end else begin
          CloseHandle(hProc);
          WriteLog('[+] Module termsrv.dll found!');
          WriteLog('[*] Searching for signatures…');

          if not SearchSignatures then begin
            M.Free;
            WriteLog('[-] Specific signature in termsrv.dll not found.');
          end else begin
            M.Free;
            if TSPatcher.cHome.Checked then
              Val1:=$EB
            else
              Val1:=$74;
            if TSPatcher.cConcur.Checked then begin
              Val2:=$75;
              Val3:=$9090;
            end else begin
              Val2:=$74;
              Val3:=$167F;
            end;
            hProc := OpenProcess(MAXIMUM_ALLOWED, False, TSPid);
            if hProc=0 then begin
              E:=GetLastError;
              WriteLog('[-] Can''t open process (Error code: '+IntToStr(E)+', '+SysErrorMessage(E)+')');
            end else begin
              GetModuleAddress('termsrv.dll', TSPid, Base, Sz);
              if not WriteProcessMemory(hProc, Pointer(Cardinal(Base)+Off1), @Val1, 1, dw) then begin
                E:=GetLastError;
                WriteLog('[-] Can''t write process memory (Error code: '+IntToStr(E)+', '+SysErrorMessage(E)+')');
              end;
              if not WriteProcessMemory(hProc, Pointer(Cardinal(Base)+Off2), @Val2, 1, dw) then begin
                E:=GetLastError;
                WriteLog('[-] Can''t write process memory (Error code: '+IntToStr(E)+', '+SysErrorMessage(E)+')');
              end;
              if not WriteProcessMemory(hProc, Pointer(Cardinal(Base)+Off3), @Val3, 2, dw) then begin
                E:=GetLastError;
                WriteLog('[-] Can''t write process memory (Error code: '+IntToStr(E)+', '+SysErrorMessage(E)+')');
              end;
              CloseHandle(hProc);
            end;
            WriteLog('[+] Required signatures found and changed!');
          end;
        end;
      end;
    end else
      WriteLog('[-] termsrv.dll library is not loaded.');
  end;
  WriteLog('[*] Updating termsrv.dll file…');
  if not FileExists(GetSystem+'system32\termsrv.dll') then
    WriteLog('[-] termsrv.dll not found in system directory.')
  else begin
    M:=TMemoryStream.Create;
    M.LoadFromFile(GetSystem+'system32\termsrv.dll');
    WriteLog('[*] Searching for signatures…');
    if not SearchSignatures then
      WriteLog('[-] Specific signature in termsrv.dll not found.')
    else begin
      if TSPatcher.cHome.Checked then
        Val1:=$EB
      else
        Val1:=$74;
      if TSPatcher.cConcur.Checked then begin
        Val2:=$75;
        Val3:=$9090;
      end else begin
        Val2:=$74;
        Val3:=$167F;
      end;
      M.Seek(Off1, soFromBeginning);
      M.WriteBuffer(Val1, 1);
      M.Seek(Off2, soFromBeginning);
      M.WriteBuffer(Val2, 1);
      M.Seek(Off3, soFromBeginning);
      M.WriteBuffer(Val3, 2);
      WriteLog('[+] Required signatures found and changed!');
    end;
    WriteLog('[*] Disabling Windows File Protection on termsrv.dll…');
    WFPKill(GetSystem+'system32\termsrv.dll');
    if not DeleteFile(GetSystem+'system32\termsrv.dll.bak') then
      WriteLog('[-] Can''t delete old backup of termsrv.dll.');
    if not RenameFile(GetSystem+'system32\termsrv.dll', GetSystem+'system32\termsrv.dll.bak') then
      WriteLog('[-] Can''t make backup of termsrv.dll.');
    WFPKill(GetSystem+'system32\termsrv.dll.bak');
    WriteLog('[*] Saving termsrv.dll…');
    try
      M.SaveToFile(GetSystem+'system32\termsrv.dll');
    except
      WriteLog('[-] Can''t save changes in termsrv.dll file.');
    end;
    if FileExists(GetSystem+'system32\dllcache\termsrv.dll') then begin
      try
        M.SaveToFile(GetSystem+'system32\dllcache\termsrv.dll');
      except

      end;
    end;
    M.Free;
    WFPKill(GetSystem+'system32\termsrv.dll');
  end;
  if TSPatcher.cDriver.Checked then begin
    WriteLog('[*] Installing RDP display redirector driver…');
    ExtractRes('devcon', GetSystem+'system32\devcon.exe');
    if not FileExists(GetSystem+'system32\devcon.exe') then
      WriteLog('[-] Can''t extract component.')
    else begin
      ExecAppAndWait('devcon.exe install "'+GetSystem+'inf\machine.inf" root\rdpdr', GetSystem+'system32');
      if not DeleteFile(GetSystem+'system32\devcon.exe') then
        WriteLog('[-] Can''t delete extracted component.');
    end;
    TSPatcher.cDriver.Checked := False;
  end;
  WriteLog('[*] Patch done.');
  TSPatcher.bApply.Enabled:=True;
  TSPatcher.cEnableTS.Enabled:=True;
  TSPatcher.cConcur.Enabled:=True;
  TSPatcher.cBlank.Enabled:=True;
  TSPatcher.cVPN.Enabled:=True;
  TSPatcher.cSingle.Enabled:=True;
  TSPatcher.cHome.Enabled:=True;
  TSPatcher.cDriver.Enabled:=True;
end;

procedure TPatchThr.Execute;
begin
  inherited;
  RunPatch;
  Status:=0;
end;

procedure TTSPatcher.FormCreate(Sender: TObject);
var
  PNG: TPNGImage;
begin
  Off1:=0;
  Off2:=0;
  Off3:=0;
  Background:=TBitmap.Create;
  PNG:=TPNGImage.Create;
  PNG.LoadFromResourceName(HInstance, 'watermark');
  Background.Assign(PNG);
  PNG.Free;
  if ParamCount=0 then begin
    SilentMode:=False;
    Init:=True;
  end else
    if ParamStr(1) = '-silent' then begin
      ShowWindow(Handle, SW_HIDE);
      ShowWindow(Application.Handle, SW_HIDE);
      SilentMode:=True;
      WriteLog('[*] Working in silent mode.');
      Init:=False;
      Step:=0;
      WriteLog('[*] Initializing…');
      EvntTimer(Sender);
      Sleep(1000);
      if bApply.Enabled then begin
        WriteLog('[*] Starting patch procedure…');
        RunPatch;
      end;
      Sleep(500);
      Halt(0);
    end;
end;

procedure TTSPatcher.FormActivate(Sender: TObject);
begin
  if not Init then
    Exit;
  Init:=False;
  Step:=0;
  Evnt.Enabled:=True;
end;

procedure TTSPatcher.bApplyClick(Sender: TObject);
begin
  bApply.Enabled:=False;
  cEnableTS.Enabled:=False;
  cConcur.Enabled:=False;
  cBlank.Enabled:=False;
  cVPN.Enabled:=False;
  cSingle.Enabled:=False;
  cHome.Enabled:=False;
  cDriver.Enabled:=False;
  PatchThr:=TPatchThr.Create(True);
  PatchThr.FreeOnTerminate:=True;
  PatchThr.Status:=4444;
  PatchThr.Start;
end;

procedure TTSPatcher.FormDestroy(Sender: TObject);
begin
  Background.Free;
end;

{ TMemo }

procedure TMemo.WMPaint(var Message: TWMPaint);
var
  MCanvas: TControlCanvas;
  DrawBounds: TRect;
  W, H: Integer;
begin
  MCanvas:=TControlCanvas.Create;
  MCanvas.Control:=Self;
  DrawBounds := ClientRect;
  W := DrawBounds.Right - DrawBounds.Left + 1;
  H := DrawBounds.Bottom - DrawBounds.Top + 1;

  inherited;

  MCanvas:=TControlCanvas.Create;
  MCanvas.Control:=Self;
  BitBlt(MCanvas.Handle, 0, 0, W, H, Background.Canvas.Handle, 0, 0, SRCPAINT);
  MCanvas.Free;
end;

procedure TTSPatcher.LogChange(Sender: TObject);
begin
  Log.Repaint;
end;

procedure TTSPatcher.LogGesture(Sender: TObject;
  const EventInfo: TGestureEventInfo; var Handled: Boolean);
begin
  Log.Repaint;
end;

procedure TTSPatcher.LogKeyDown(Sender: TObject; var Key: Word;
  Shift: TShiftState);
begin
  Log.Repaint;
end;

procedure TTSPatcher.LogKeyPress(Sender: TObject; var Key: Char);
begin
  Log.Repaint;
end;

procedure TTSPatcher.LogMouseActivate(Sender: TObject; Button: TMouseButton;
  Shift: TShiftState; X, Y, HitTest: Integer;
  var MouseActivate: TMouseActivate);
begin
  Log.Repaint;
end;

procedure TTSPatcher.LogMouseDown(Sender: TObject; Button: TMouseButton;
  Shift: TShiftState; X, Y: Integer);
begin
  Log.Repaint;
end;

procedure TTSPatcher.LogMouseMove(Sender: TObject; Shift: TShiftState; X,
  Y: Integer);
begin
  Log.Repaint;
end;

end.
