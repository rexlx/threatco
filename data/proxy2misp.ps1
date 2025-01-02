param (
    [Parameter(Mandatory=$true)]
    [string]$value
)

# Define the URL and headers
$url = "http://localhost:8081/pipe"
$headers = @{
    "Authorization" = "beep@boop.com:bOtHGzBR+XXGEozPnoyXzo7192eJ1NeN3QtdgNaMXPE="
    "Content-Type" = "application/json"
}

# Define the body
$body = @{
    value = $value
    to = "misp"
    type = "ipv4"
} | ConvertTo-Json

# Make the POST request
Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $body -SkipCertificateCheck