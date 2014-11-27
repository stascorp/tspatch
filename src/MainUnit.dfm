object TSPatcher: TTSPatcher
  Left = 0
  Top = 0
  BorderIcons = [biSystemMenu]
  BorderStyle = bsDialog
  Caption = 'Windows XP (x86) Terminal Services Realtime Patch by Stas'#39'M'
  ClientHeight = 300
  ClientWidth = 406
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  Position = poScreenCenter
  OnActivate = FormActivate
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  PixelsPerInch = 96
  TextHeight = 13
  object Log: TMemo
    Left = 0
    Top = 0
    Width = 406
    Height = 215
    Align = alClient
    Color = clBlack
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clSilver
    Font.Height = -11
    Font.Name = 'Courier New'
    Font.Style = []
    Lines.Strings = (
      'Terminal Services Realtime Patch by Stas'#39'M'
      'Copyright '#169' Stas'#39'M Corp. 2012'
      'http://stascorp.com'
      '______________________________________________________'
      ''
      '*** Licensed under the Apache License, Version 2.0,'
      '*** see LICENSE file in the project root folder.'
      '______________________________________________________'
      '')
    ParentFont = False
    ReadOnly = True
    ScrollBars = ssVertical
    TabOrder = 0
    OnChange = LogChange
    OnClick = LogChange
    OnDblClick = LogChange
    OnEnter = LogChange
    OnExit = LogChange
    OnGesture = LogGesture
    OnKeyDown = LogKeyDown
    OnKeyPress = LogKeyPress
    OnKeyUp = LogKeyDown
    OnMouseActivate = LogMouseActivate
    OnMouseDown = LogMouseDown
    OnMouseEnter = LogChange
    OnMouseLeave = LogChange
    OnMouseMove = LogMouseMove
    OnMouseUp = LogMouseDown
  end
  object MainPanel: TPanel
    Left = 0
    Top = 215
    Width = 406
    Height = 85
    Align = alBottom
    BevelOuter = bvNone
    TabOrder = 1
    object cConcur: TCheckBox
      Left = 8
      Top = 23
      Width = 145
      Height = 17
      Caption = 'Allow concurrent &sessions'
      Enabled = False
      TabOrder = 0
    end
    object cHome: TCheckBox
      Left = 163
      Top = 40
      Width = 163
      Height = 17
      Caption = 'Turn on &Home Edition support'
      Enabled = False
      TabOrder = 1
      OnClick = cHomeClick
    end
    object cBlank: TCheckBox
      Left = 8
      Top = 40
      Width = 136
      Height = 17
      Caption = 'Enable &blank passwords'
      Enabled = False
      TabOrder = 2
    end
    object cVPN: TCheckBox
      Left = 163
      Top = 6
      Width = 181
      Height = 17
      Caption = 'Keep alive &VPN (RAS) connections'
      Enabled = False
      TabOrder = 3
    end
    object bApply: TButton
      Left = 8
      Top = 58
      Width = 70
      Height = 20
      Caption = '&Apply'
      Enabled = False
      TabOrder = 4
      OnClick = bApplyClick
    end
    object bClose: TButton
      Left = 84
      Top = 58
      Width = 69
      Height = 20
      Caption = '&Close'
      TabOrder = 5
      OnClick = bCloseClick
    end
    object cDriver: TCheckBox
      Left = 163
      Top = 57
      Width = 191
      Height = 17
      Caption = 'Install &RDP display redirector driver'
      Enabled = False
      TabOrder = 6
      Visible = False
    end
    object cEnableTS: TCheckBox
      Left = 8
      Top = 6
      Width = 132
      Height = 17
      Caption = 'Enable remote &desktop'
      Enabled = False
      TabOrder = 7
    end
    object cSingle: TCheckBox
      Left = 163
      Top = 23
      Width = 132
      Height = 17
      Caption = 'Single session per &user'
      Enabled = False
      TabOrder = 8
    end
  end
  object Evnt: TTimer
    Enabled = False
    Interval = 100
    OnTimer = EvntTimer
    Left = 336
    Top = 8
  end
end
