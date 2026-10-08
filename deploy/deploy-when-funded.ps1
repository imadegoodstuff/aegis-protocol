# Poll the deployer EOA balance on Sepolia. Deploy as soon as it's funded.
# Usage: pwsh deploy-when-funded.ps1
# Run on any shell with Node + the deploy/package.json installed.

$ADDR = "0x67bb01F5DA6BD332Fa50271B2F4FF4957Cbe629C"
$RPC  = "https://11155111.rpc.thirdweb.com"

Write-Host "Polling Sepolia balance of $ADDR every 10 s. Ctrl+C to stop."
Write-Host "To fund it: https://sepolia-faucet.pk910.de/   (PoW, no login)"
Write-Host "            https://cloud.google.com/application/web3/faucet/ethereum/sepolia"
Write-Host ""

while ($true) {
  $body = @{
    jsonrpc = "2.0"; method = "eth_getBalance"
    params = @($ADDR, "latest"); id = 1
  } | ConvertTo-Json -Compress
  try {
    $r = Invoke-RestMethod -Uri $RPC -Method Post -ContentType "application/json" -Body $body -TimeoutSec 15
    $bal = [uint64]("0x" + $r.result.Substring(2))
    $ether = $bal / 1e18
    $ts = (Get-Date).ToString("HH:mm:ss")
    Write-Host "[$ts] balance: $($ether.ToString('F6')) ETH"
    if ($bal -ge 5000000000000000) {  # 0.005 ETH
      Write-Host "`n✓ Funded! Deploying..."
      cd $PSScriptRoot
      node deploy.mjs sepolia
      exit 0
    }
  } catch {
    Write-Host "RPC err: $_"
  }
  Start-Sleep -Seconds 10
}
