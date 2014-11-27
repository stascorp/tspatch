Terminal Services Realtime Patch for Windows XP by Stas'M
=======

Terminal Services Realtime Patch by Stas'M allows you to patch remote desktop concurrent sessions on Windows XP box and also able to unlock remote desktop on Windows XP Home Edition. And you don't need to change your OS edition or reboot the computer. Patch works in realtime in 2 stages:<br>
- <u>Stage 1:</u><br>
Apply patch to the Terminal Services process memory (that's why no reboot required).
- <u>Stage 2:</u><br>
Patch the termsrv.dll in the system folder.
 
Also it can install RDP display redirector driver (rdpdr.sys) with devcon utility (built-in program).
 
And there are some useful features (tweaks):
- Keep alive VPN connections (such as PPTP or PPPoE)
- Single or multiple sessions per user
- Enable or disable blank passwords on remote logon
 
Attention:<br>
This patcher support only Windows XP (Service Pack 2 and 3) and x86 system architecture.<br>
Now we are trying to make patching support for SP 1 (termsrv.dll version 5.1.2600.1106).
 
Video instruction (how to enable RDP on Windows XP Home Edition):<br>
http://www.youtube.com/watch?v=slG5paz8r8E
 
References:<br>
http://wasm.ru/forum/viewtopic.php?pid=404047<br>
http://fouroom.ru/viewtopic.php?id=347 (post #8)
 
Other patchers:
- RDP Wrapper Library by Stas'M (Windows Vista, Windows 7, Windows 8) - no reboot<br>
https://github.com/binarymaster/rdpwrap
- Universal Termsrv.dll Patch (x86/x64) by deepxw - reboot required<br>
http://deepxw.blogspot.ru/2009/04/universal-termsrvdll-patch.html
- Concurrent RDP Patcher (Windows 7 RTM) by untermensch - no reboot<br>
http://experts.windows.com/frms/windows_entertainment_and_connected_home/f/114/t/79427.aspx
- Windows 8 Patcher by Peter Kleissner - reboot required<br>
http://forums.mydigitallife.info/threads/31829-Windows-8-Patcher
