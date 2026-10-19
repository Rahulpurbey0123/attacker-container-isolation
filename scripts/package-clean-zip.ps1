param(
    [string]$ZipPath = "C:\Users\rahul\secure-attacker.zip",
    [switch]$SkipExtractionCheck = $false
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.IO.Compression.FileSystem

$sourceDir = Resolve-Path "$PSScriptRoot\.."
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "SECURE PACKAGING UTILITY FOR ATTACKER CONTAINER ISOLATION" -ForegroundColor Cyan
Write-Host "Source directory: $sourceDir"
Write-Host "Target archive:   $ZipPath"
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Validation of target path
$targetDir = Split-Path -Path $ZipPath -Parent
if (-not (Test-Path $targetDir)) {
    New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
}

# Ensure destination zip is outside the project root
$sourcePathResolved = (Resolve-Path $sourceDir).Path.TrimEnd('\')
$sourcePathWithSlash = $sourcePathResolved + "\"
if ($ZipPath.StartsWith($sourcePathWithSlash, [System.StringComparison]::OrdinalIgnoreCase) -or ($ZipPath -eq $sourcePathResolved)) {
    Write-Error "CRITICAL: The destination ZIP cannot be located inside the project source tree ($sourceDir)."
    exit 1
}

# 2. Setup temporary clean staging directory
$stageId = [System.Guid]::NewGuid().ToString("N").Substring(0, 8)
$stageDir = Join-Path $env:TEMP "secure-attacker-stage-$stageId"
if (Test-Path $stageDir) {
    Remove-Item $stageDir -Recurse -Force
}
New-Item -ItemType Directory -Path $stageDir -Force | Out-Null
Write-Host "[1/6] Created clean staging environment: $stageDir" -ForegroundColor Green

# 3. Directory and file exclusion patterns
$excludedDirNames = @(".git", "node_modules", ".vscode", ".idea", "scratch", "dist", "build")
$excludedFilePatterns = @(
    "*kubeconfig*.yaml",
    "*kubeconfig*.yml",
    "*.env*",
    "*.token",
    "*.key",
    "*.pem",
    "*.bak",
    "*.swp",
    "*.swo",
    "*~",
    "*.tmp",
    "*.temp",
    "*.log",
    ".DS_Store",
    "Thumbs.db",
    "desktop.ini"
)

# 4. Copy files to staging with strict filtering
Write-Host "[2/6] Staging project files with exclusion filtering..." -ForegroundColor Green
$allFiles = Get-ChildItem -Path $sourceDir -Recurse -File -Force

$copiedCount = 0
$excludedCount = 0

foreach ($file in $allFiles) {
    $relativePath = $file.FullName.Substring($sourcePathResolved.Length).TrimStart('\', '/')
    $pathSegments = $relativePath.Split([char[]]@('\', '/'), [System.StringSplitOptions]::RemoveEmptyEntries)

    # Check if any parent directory is excluded
    $dirExcluded = $false
    foreach ($seg in $pathSegments[0..($pathSegments.Length - 2)]) {
        if ($excludedDirNames -contains $seg.ToLower()) {
            $dirExcluded = $true
            break
        }
    }

    if ($dirExcluded) {
        $excludedCount++
        continue
    }

    # Check if filename matches any exclusion pattern
    $fileExcluded = $false
    foreach ($pattern in $excludedFilePatterns) {
        if ($file.Name -like $pattern) {
            $fileExcluded = $true
            break
        }
    }

    if ($fileExcluded) {
        $excludedCount++
        continue
    }

    # Copy allowed file to staging directory
    $destinationFile = Join-Path $stageDir $relativePath
    $destinationDir = Split-Path -Path $destinationFile -Parent
    if (-not (Test-Path $destinationDir)) {
        New-Item -ItemType Directory -Path $destinationDir -Force | Out-Null
    }

    Copy-Item -Path $file.FullName -Destination $destinationFile -Force
    $copiedCount++
}

# Ensure orchestrator/logs directory exists with a placeholder .gitkeep
$logsDir = Join-Path $stageDir "orchestrator\logs"
if (-not (Test-Path $logsDir)) {
    New-Item -ItemType Directory -Path $logsDir -Force | Out-Null
}
$gitkeepPath = Join-Path $logsDir ".gitkeep"
if (-not (Test-Path $gitkeepPath)) {
    Set-Content -Path $gitkeepPath -Value "# Log directory placeholder - runtime logs generated during execution" -Force
}

Write-Host "      Staged $copiedCount files (Filtered out $excludedCount files and directory entries)"

# 5. Pre-packaging security & credential scanning of staged files
Write-Host "[3/6] Scanning staged files for prohibited secrets..." -ForegroundColor Green

$stagedFiles = Get-ChildItem -Path $stageDir -Recurse -File
$secretDetected = $false
$scannedTextCount = 0


foreach ($sFile in $stagedFiles) {
    # Scan text files only
    if ($sFile.Extension -in @(
        ".js", ".json", ".yaml", ".yml", ".md",
        ".ps1", ".sh", ".html", ".css", ".txt",
        ".xml", ".config", ".properties", ".env"
    )) {
        $scannedTextCount++

        $content = Get-Content -Path $sFile.FullName -Raw -ErrorAction SilentlyContinue

        if ($null -ne $content) {
            # Check for private-key headers
            if ($content -match '-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----') {
                Write-Error "SECURITY GATE: Private key detected in staged file: $($sFile.Name)"
                $secretDetected = $true
            }

            # Check for Kubernetes service-account token fields
            if ($content -match '(?m)^\s*token:\s*["'']?[A-Za-z0-9_.-]{30,}') {
                Write-Error "SECURITY GATE: Possible Kubernetes token detected in staged file: $($sFile.Name)"
                $secretDetected = $true
            }

            # Check for bearer JWT tokens
            if ($content -match '(?i)Bearer\s+eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}') {
                Write-Error "SECURITY GATE: Possible bearer token detected in staged file: $($sFile.Name)"
                $secretDetected = $true
            }

            # Check for common credential assignments
            if ($content -match '(?im)(api[_-]?key|client[_-]?secret|secret[_-]?key|access[_-]?token|password)\s*[:=]\s*["'']?[A-Za-z0-9_./+=-]{20,}') {
                Write-Error "SECURITY GATE: Possible credential assignment detected in staged file: $($sFile.Name)"
                $secretDetected = $true
            }

            # Check for common cloud access-key IDs
            if ($content -match '\bAKIA[0-9A-Z]{16}\b') {
                Write-Error "SECURITY GATE: Possible cloud access-key ID detected in staged file: $($sFile.Name)"
                $secretDetected = $true
            }
        }
    }
}


if ($secretDetected) {
    Remove-Item $stageDir -Recurse -Force
    Write-Error "SECURITY GATE FAILURE: Secret pattern detected in staged files. Packaging aborted."
    exit 1
}
Write-Host "      Verified $scannedTextCount text files. Zero credentials or private keys detected."

# 6. Compress staging folder into clean ZIP
Write-Host "[4/6] Creating compressed archive at $ZipPath..." -ForegroundColor Green
if (Test-Path $ZipPath) {
    throw "SAFETY STOP: ZIP already exists at '$ZipPath'. Choose a new filename; existing archives will not be overwritten."
}

[System.IO.Compression.ZipFile]::CreateFromDirectory($stageDir, $ZipPath, [System.IO.Compression.CompressionLevel]::Optimal, $false)

$zipItem = Get-Item $ZipPath
$zipSizeKb = [math]::Round($zipItem.Length / 1024, 2)
$zipSizeMb = [math]::Round($zipItem.Length / 1MB, 2)
Write-Host "      Archive created successfully: $zipSizeKb KB ($zipSizeMb MB)"

# Fail-safe size gate: source code archive must be < 5 MB
if ($zipItem.Length -gt 5MB) {
    Write-Error "SECURITY GATE FAILURE: Archive size ($zipSizeMb MB) exceeds safety threshold (5 MB). Unwanted binaries or node_modules may be included."
    exit 1
}

# 7. Post-Packaging Inspection of Archive Entries
Write-Host "[5/6] Inspecting archive contents..." -ForegroundColor Green
$zipArchive = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
$prohibitedFound = @()
$entryNames = @()

foreach ($entry in $zipArchive.Entries) {
    $entryNames += $entry.FullName
    $nameLower = $entry.FullName.ToLower()

    if ($nameLower -match "(^|/|\\)\.git($|/|\\)") { $prohibitedFound += $entry.FullName }
    if ($nameLower -match "(^|/|\\)node_modules($|/|\\)") { $prohibitedFound += $entry.FullName }
    if ($nameLower -match "kubeconfig.*\.ya?ml$") { $prohibitedFound += $entry.FullName }
    if ($nameLower -match "\.env(\.|$).*") { $prohibitedFound += $entry.FullName }
    if ($nameLower -match "\.bak$") { $prohibitedFound += $entry.FullName }
    if ($nameLower -match "\.log$") { $prohibitedFound += $entry.FullName }
    if ($nameLower -match "\.pem$") { $prohibitedFound += $entry.FullName }
    if ($nameLower -match "\.key$") { $prohibitedFound += $entry.FullName }
}
$zipArchive.Dispose()

if ($prohibitedFound.Count -gt 0) {
    Write-Error "SECURITY GATE FAILURE: Prohibited files detected in final ZIP: $($prohibitedFound -join ', ')"
    exit 1
}

# Verify required core files exist
$requiredFiles = @(
    "orchestrator/index.js",
    "orchestrator/package.json",
    "orchestrator/package-lock.json",
    "orchestrator/providers/k8s-provider.js",
    "orchestrator/providers/docker-provider.js",
    "orchestrator/security/validator.js",
    "kubernetes/namespace.yaml",
    "kubernetes/attacker-pod.yaml",
    "kubernetes/network-policy.yaml",
    "docs/REMEDIATION_REPORT.md",
    "docs/FINAL_VERIFICATION.md",
    "docs/DEMO_RUNBOOK.md",
    "Dockerfile",
    "dashboard/index.html"
)

$missingRequired = @()
foreach ($req in $requiredFiles) {
    $normalizedReq = $req.Replace('\', '/')
    $found = $false
    foreach ($en in $entryNames) {
        if ($en.Replace('\', '/') -eq $normalizedReq) {
            $found = $true
            break
        }
    }
    if (-not $found) {
        $missingRequired += $req
    }
}

if ($missingRequired.Count -gt 0) {
    Write-Error "VALIDATION FAILURE: Required project files are missing from archive: $($missingRequired -join ', ')"
    exit 1
}
Write-Host "      All $($requiredFiles.Count) essential core project files verified present."
Write-Host "      Zero prohibited directories or sensitive files found in archive."

# 8. Test extraction gate
if (-not $SkipExtractionCheck) {
    Write-Host "[6/6] Testing archive extraction and structural integrity..." -ForegroundColor Green
    $extractDir = Join-Path $env:TEMP "secure-attacker-extract-verify-$stageId"
    if (Test-Path $extractDir) {
        Remove-Item $extractDir -Recurse -Force
    }
    New-Item -ItemType Directory -Path $extractDir -Force | Out-Null

    [System.IO.Compression.ZipFile]::ExtractToDirectory($ZipPath, $extractDir)

    # Test JS syntax of extracted codebase
    $testFiles = @(
        "orchestrator\index.js",
        "orchestrator\security\validator.js",
        "orchestrator\providers\k8s-provider.js",
        "orchestrator\providers\docker-provider.js"
    )

    foreach ($tf in $testFiles) {
        $extractedFilePath = Join-Path $extractDir $tf
        if (-not (Test-Path $extractedFilePath)) {
            Write-Error "EXTRACTION CHECK FAILURE: File not found in extracted archive: $tf"
            exit 1
        }
        $syntaxCheck = & node --check $extractedFilePath 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Error "EXTRACTION CHECK FAILURE: Syntax check failed on extracted file $tf : $syntaxCheck"
            exit 1
        }
    }
    Write-Host "      Extracted successfully. JavaScript syntax validation passed on extracted files."

    # Clean up extraction verification directory
    Remove-Item $extractDir -Recurse -Force
}

# Clean up staging directory
Remove-Item $stageDir -Recurse -Force

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "PACKAGING SUCCESSFUL & VERIFIED" -ForegroundColor Cyan
Write-Host "Archive location: $ZipPath"
Write-Host "Archive size:     $zipSizeKb KB"
Write-Host "============================================================" -ForegroundColor Cyan
