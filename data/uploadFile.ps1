param(
    [string]$filePath,
    [string]$serverUrl = "http://localhost:8081"
)

# Calculate the file size
$fileSize = (Get-Item $filePath).Length

# Set the chunk size (adjust as needed)
$chunkSize = 1MB

# Read the file content
$fileContent = Get-Content $filePath -Raw

# Calculate the number of chunks
$totalChunks = [Math]::Ceiling($fileSize / $chunkSize)
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

# Loop through the chunks
for ($i = 0; $i -lt $totalChunks; $i++) {
    # Calculate the chunk offset and length
    $offset = $i * $chunkSize
    $length = [Math]::Min($chunkSize, $fileSize - $offset)

    # Extract the chunk data
    $chunkData = $fileContent.Substring($offset, $length)

    # Create the web request
    $request = [System.Net.WebRequest]::Create("$serverUrl/upload")
    $request.Method = "POST"
    $request.Headers.Add("Authorization", "")
    $request.Headers.Add("X-filename", (Split-Path $filePath -Leaf))
    $request.Headers.Add("X-last-chunk", ($i -eq ($totalChunks - 1)))
    $request.ContentLength = $length

    # Write the chunk data to the request stream
    $requestStream = $request.GetRequestStream()
    $requestStream.Write([System.Text.Encoding]::UTF8.GetBytes($chunkData), 0, $length)
    $requestStream.Close()

    # Get the response
    $response = $request.GetResponse()
    $response.Close()

    Write-Host "Uploaded chunk $($i + 1) of $totalChunks"
}

Write-Host "File uploaded successfully!"