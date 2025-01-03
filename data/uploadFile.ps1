param (
    [Parameter(Mandatory=$true)]
    [string]$filePath,
    [Parameter(Mandatory=$true)]
    [string]$url
)

# Check if the file exists
if (-Not (Test-Path -Path $filePath)) {
    Write-Host "File not found: $filePath"
    exit 1
}

# Read the file content
$fileContent = Get-Content -Path $filePath -Raw

# Define the headers
$headers = @{
    "Content-Type" = "application/octet-stream"
    "X-filename" = [System.IO.Path]::GetFileName($filePath)
    "X-last-chunk" = "true"  # Assuming this is the last chunk
}

[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
# Make the POST request
$response = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $fileContent -SslProtocol tls12

# Output the response
Write-Host "Response: $($response | ConvertTo-Json -Depth 10)"