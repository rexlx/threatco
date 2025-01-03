param (
    [Parameter(Mandatory=$true)]
    [string]$filePath,
    [Parameter(Mandatory=$true)]
    [string]$url,
    [int]$chunkSize = 1048576  # Default chunk size is 1MB
)

# Check if the file exists
if (-Not (Test-Path -Path $filePath)) {
    Write-Host "File not found: $filePath"
    exit 1
}

# Get the file name
$fileName = [System.IO.Path]::GetFileName($filePath)

# Open the file stream
$fileStream = [System.IO.File]::OpenRead($filePath)
$buffer = New-Object byte[] $chunkSize
$bytesRead = 0
$chunkNumber = 0

try {
    while (($bytesRead = $fileStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
        $chunkNumber++
        $isLastChunk = $fileStream.Position -eq $fileStream.Length

        # Define the headers
        $headers = @{
            "Content-Type" = "application/octet-stream"
            "X-filename" = $fileName
            "X-last-chunk" = $isLastChunk.ToString()
        }

        # Get the actual bytes read
        $chunkData = if ($bytesRead -eq $buffer.Length) { $buffer } else { $buffer[0..($bytesRead - 1)] }

        # Make the POST request
        $response = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $chunkData

        # Output the response
        Write-Host "Chunk $chunkNumber response: $($response | ConvertTo-Json -Depth 10)"
    }
} finally {
    $fileStream.Close()
}