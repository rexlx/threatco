# chromeand
use the chrome devtools protocol to automate browser tests

## starting the browser in windows
Start-Process "C:\Program Files\Google\Chrome\Application\chrome.exe" -ArgumentList "--remote-debugging-port=9222", "--user-data-dir=C:\temp\chrome-automation"
