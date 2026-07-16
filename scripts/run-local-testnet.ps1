#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Starts two local Aeon nodes (node A and node B, node B connected to
    node A) for testing mining and transactions between two wallets on a
    single machine. See docs/GETTING_STARTED.md and docs/MINING.md.

.DESCRIPTION
    Builds the workspace in release mode, then launches two `aeon-node`
    processes in new windows:
      - Node A: data in ./node-a-data, P2P on 16110, RPC on 16111
      - Node B: data in ./node-b-data, P2P on 16120, RPC on 16121, connected to node A

    Press Ctrl+C in each node's window to stop it.
#>

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host "Building Aeon in release mode (first run may take a few minutes)..."
cargo build --release --workspace

$binDir = Join-Path $root "target\release"

Write-Host "Starting node A (P2P 127.0.0.1:16110, RPC 127.0.0.1:16111)..."
Start-Process -FilePath (Join-Path $binDir "aeon-node.exe") -ArgumentList @(
    "--datadir", "./node-a-data",
    "--p2p-listen", "127.0.0.1:16110",
    "--rpc-listen", "127.0.0.1:16111"
) -WorkingDirectory $root

Start-Sleep -Seconds 2

Write-Host "Starting node B (P2P 127.0.0.1:16120, RPC 127.0.0.1:16121), connected to node A..."
Start-Process -FilePath (Join-Path $binDir "aeon-node.exe") -ArgumentList @(
    "--datadir", "./node-b-data",
    "--p2p-listen", "127.0.0.1:16120",
    "--rpc-listen", "127.0.0.1:16121",
    "--addnode", "127.0.0.1:16110"
) -WorkingDirectory $root

Write-Host ""
Write-Host "Two nodes are starting in separate windows."
Write-Host "Node A RPC: http://127.0.0.1:16111"
Write-Host "Node B RPC: http://127.0.0.1:16121"
Write-Host ""
Write-Host "Next steps (see docs/GETTING_STARTED.md):"
Write-Host "  cargo run --release -p aeon-wallet -- create --wallet alice.json"
Write-Host "  cargo run --release -p aeon-wallet -- create --wallet bob.json"
Write-Host "  cargo run --release -p aeon-miner -- --node http://127.0.0.1:16111 --address <alice's address>"
Write-Host "  cargo run --release -p aeon-wallet -- balance --wallet alice.json --node http://127.0.0.1:16111"
Write-Host "  cargo run --release -p aeon-wallet -- send --wallet alice.json --node http://127.0.0.1:16111 --to <bob's address> --amount 5.0"
Write-Host "  cargo run --release -p aeon-wallet -- balance --wallet bob.json --node http://127.0.0.1:16121   # a different node — proves P2P propagation"
