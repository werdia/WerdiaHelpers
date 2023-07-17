using namespace System
using namespace Diagnostics.CodeAnalysis
using namespace Microsoft.Dism.Commands
using module DISM

#region Files and Paths

<#
.SYNOPSIS
    Replace .\ in strings with current working directory.
#>
Function AsFullPath {
    [SuppressMessageAttribute("PSUseApprovedVerbs", Scope="Module")]
    param(
        [Parameter(ValueFromPipeline)]$pl
    )
    begin{
        # NOTE: If declared cmdlet, $psCmdLet automatic variable replaces $args
        <#if($args.Length -ge 0){
            # Executed if $pl is not from pipeline (in addition to process block)
        }#>
    }
    process{
        $pl | ForEach-Object{$_ -replace ([regex]::Escape('.\')),"$PWD\"}
    }
}

<#
.SYNOPSIS
    Look for traditional %var% style references to environment variables and replace
    them with values.
.PARAMETER str
    Input string.
#>
Function Expand-Path {
    [CmdletBinding()]
    [OutputType([String])] # unfortunately no error is produced if control flow ends without return statement
    Param(
        [Parameter(Mandatory = $true)] [String]$str
    )
    # if string contains a % then process it
    if ($str -match "%\S+%") {
        # split string into an array of values, filter away zero-length strings
        $values = $str.split("%") | Where-Object { $_ }
        foreach ($text in $values) {
            # find the corresponding value in ENV
            [string]$replace = (Get-Item env:$text -erroraction "SilentlyContinue").Value
            if ($replace) {
                $expandedPath += $replace
            }
            else { $expandedPath += $text }
        }
        return $expandedPath
    }
    else { return $str }
}

<#
.SYNOPSIS
    List paths that match patterning
.EXAMPLE
    Find-MatchingPaths -SearchRoot HKCU:\ -NameFilters @('CurrentVersion') -Attributes @{}
#>
Function Find-MatchingPaths {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] $SearchRoot,
        # Exact item name matches
        [Parameter(Mandatory = $true)] $NameFilters,
        # Regular expression filters for item names (default will match nothing)
        [Parameter(Mandatory = $false)] $PatternFilters = @('a^'),
        # Exact match for ending of the full item path. Path being matched has no \
        # at its end.
        [Parameter(Mandatory = $false)] $PathFilters = @(),
        [Parameter(Mandatory = $false)] $Attributes = @{Directory = $true},
        [Parameter(Mandatory = $false)] $OutputFormat = "{0}`r`n",
        # Display real-time console output of matches
        [Parameter(Mandatory = $false)] [Switch]$Print,
        # Write output to text file
        [Parameter(Mandatory = $false)] [String]$ToFile
    )
    $ErrorActionPreference = 'SilentlyContinue'
    Function Recurse($path) {
        $allChildItems = Get-ChildItem -Path "$path" -Name -Force @Attributes
        $matchedPaths = @()
        foreach ($c in $allChildItems)
        {
            $cPath = "$path\$c"
            $nameMatch = ($NameFilters -eq $c).Length -gt 0
            $patternMatch = $c -match "($PatternFilters)"
            $pathMatch = (Where-Object $PathFilters {$cPath.EndsWith($_)}).Length -gt 0
            if($nameMatch -or $patternMatch -or $pathMatch)
            {
                $matchType = if($nameMatch){"name"} else{if($patternMatch) {"pattern"} else {"path"}}
                if($Print) { Write-Host "New match:" $cPath "($matchType)" }
                $matchedPaths += $cPath
            }
            else{
                # Write-Host "Recurse to:" $cPath
                $other = Recurse($cPath)
                $matchedPaths += $other
            }
        }
        return $matchedPaths
    }
    $outputPaths = Recurse $SearchRoot
    $ErrorActionPreference = 'Continue'
    $outputStrs = $outputPaths | ForEach-Object -Process {($OutputFormat -f $_)}
    if($ToFile){
        -join $outputStrs | Out-File -FilePath $ToFile -NoClobber
    } else { return (-join $outputStrs) }
}

<#
.SYNOPSIS
    Get file system path of a "special folder" (Windows)
.PARAMETER Identifier
    Identifier of the folder. If none is supplied, the command will print
    out the most commonly needed paths.
#>
Function Get-SpecialFolder
{
    [CmdletBinding()]
    [OutputType([String])]
    Param(
        [Parameter(Mandatory = $false)] [String]$Identifier
    )
    if($Identifier)
    {
        $folderKind = [Enum]::Parse([Environment+SpecialFolder], $Identifier)
        return [Environment]::GetFolderPath($folderKind)
    }
    else
    {
        $desktop = Get-SpecialFolder "Desktop"
        $desktopd = Get-SpecialFolder "DesktopDirectory"
        $documents = Get-SpecialFolder "MyDocuments"
        $templates = Get-SpecialFolder "Templates"
        Write-Host "Desktop:         " $desktop
        Write-Host "DesktopDirectory:" $desktopd
        Write-Host "MyDocuments:     " $documents
        Write-Host "Templates        " $templates
    }
}

<#
.SYNOPSIS
    Get identifier for each special folder.
#>
Function Get-SpecialFolderIdentifiers
{
    [Enum]::GetValues([Environment+SpecialFolder])
}

<#
.SYNOPSIS
    Hash all or some files (non-hidden and non-system) files of a
    path and either print hashes or rename files after the values.
.EXAMPLE
    HashFiles -Path c:\temp [-Rename] [-Recurse]
#>
Function HashFiles
{
    [CmdletBinding()]
    Param(
        [ValidateScript({ Test-Path $_ })] $Path,
        [String]$Extension = '*',
        [Switch]$Rename,
        [Switch]$Recurse,
        [String]$Algorithm = 'SHA1'
    )
    $hasher = [System.Security.Cryptography.HashAlgorithm]::Create($Algorithm)
    $files = Get-ChildItem $Path -Include ('*.' + $Extension) -Recurse:$Recurse |
     Where-Object { -not $_.PSIsContainer } # exclude directories
    foreach ($file in $files)
    {
        $fileContentStream = New-Object IO.FileStream($file.FullName, 'Open', 'Read', 'Read')
        $hash = ($hasher.ComputeHash($fileContentStream)).ToString("X2") # X2 is hex format
        $fileContentStream.Close()
        if($Rename){
            $newName = $hash + $file.Extension
            if(-not (Test-Path ($file.DirectoryName + $newName) )){
                $file | Rename-Item -NewName $newName
            }
            else {
                Write-Host "Failed to rename " + $file.Name
            }
        }
        else{
            Write-Host ($file.Name + ": " + $hash)
        }
    }
}

#endregion

#region Miscellaneous

<#
.SYNOPSIS
    Cached item may cause occasional malfunctions in Visual Studio Code. This command will clear caches.
#>
Function Clear-VsCodeCaches
{
    $userResponse = Read-Host -Prompt "Clear cache files for Visual Studio Code? [Y]"
    if($userResponse -eq "Y" -or $userResponse -eq "")
    {
        if(!Test-Path $env:APPDATA\Code)
        {
            Write-ErrorMessage "Visual Studio Code path not found: exiting"
            return
        }
        Remove-Item -Force -Path $env:APPDATA\Code\Cache\*
        Remove-Item -Force -Path $env:APPDATA\Code\CachedData\*
        Remove-Item -Force -Path $env:APPDATA\Code\CacheExtensions\*
        Remove-Item -Force -Path $env:APPDATA\Code\CachedExtensionVSIXs\*
        Remove-Item -Force -Path "$env:APPDATA\Code\Code Cache\*"
        Write-Host "Caches cleared"
    }
    else
    {
        Write-Host "Task cancelled by user"
    }
}

#endregion

#region PowerShell

<#
.SYNOPSIS
    Adds "type accelerator, which is essentially alias for CLR classes
#>
Function Add-TypeAccelerator
{
    [CmdletBinding()]
    param(
        [string]$AliasName,
        [string]$TrueClassName
    )
    # Need to get the Runtime types dynamically as in here
    $accType = [PowerShell].Assembly.GetType("System.Management.Automation.TypeAccelerators")
    # Note the brackets around $TrueClassName to denote class
    $accTypeAddExpression = "`$accType::Add(`"$AliasName`",[$TrueClassName])"
    Invoke-Expression $accTypeAddExpression
    $builtInField = $accType.GetField( # the field is Dictionary<String, Type>
        "builtinTypeAccelerators",
        [System.Reflection.BindingFlags]"Static,NonPublic")
    # We have already invoked accType::Add, which is reflected in ::Get
    $builtInField.SetValue($builtInField, $accType::Get)
}

<#
.SYNOPSIS
    Convert (if needed) path string to PS object representing the file or directory.
#>
Function AsFileObject
{
    [CmdletBinding()]
    param(
        $item,
        [bool]$folder = $false
    )
    Write-Debug -Message ("Item Type:" + $item.GetType())
    Switch($item.GetType().GUID)
    {
        ([System.String].GUID){
            if(Test-Path -Path $item){
                $getItem = Get-Item $item
                AsFileObject $getItem $folder
            } else{ Write-Error "Invalid path"; $null }
        }
        ([System.IO.FileInfo].GUID){
            if(-not $item.PSIsContainer) {
                # is file
                if($folder) {Write-Error "Not a folder"; $null} else {$item}
            } else {
                # is folder
                if($folder) {$item} else { Write-Error "Not a folder"; $null }
            }
        }
        ([System.IO.DirectoryInfo].GUID){
            # is folder
            if($folder) {$item} else { Write-Error "Not a file"; $null }
        }
        default{
            Write-Error "Unknown input type"; $null
        }
    }
}

<#
.SYNOPSIS
    Debug helper that displays information about an object.
#>
Function Identity
{
    Param(
        [Parameter(Mandatory = $true)] $I,
        [Parameter(Mandatory = $false)] [Switch]$AsString
    )
    $t = $I.GetType()
    Write-Host "Is of Type: " $t.FullName "(IsClass:" $t.IsClass ")"
    Write-Host "From Module:" $t.Module.Name
    if($AsString){
        Write-Host "To String:  " $I.ToString()
    }
    $I | Format-List
}

<#
.SYNOPSIS
    Checks status of a bit
#>
function IsBitSet
{
    param (
        [Parameter(Mandatory = $true)] [int]$I,
        [Parameter(Mandatory = $true)] [int]$Bit
    )
    ($I -band $Bit) -ne 0
}

<#
.SYNOPSIS
    Remove empty strings from the pipe
#>
Filter NonEmptyStrings
{
    if ($_.Length -ge 0) {
        return $_
    }
}

<#
.SYNOPSIS
    Produces a new string by repetition
#>
Function Get-RepeatedString
{
    [CmdletBinding()]
    [OutputType([String])]
    # NOTE: This attribute can only be placed before param block.
    [SuppressMessageAttribute("PSUseApprovedVerbs", Scope="function", Target="_*")]
    param(
        [string]$S,
        [uint]$Times
    )
    -join [System.Linq.Enumerable]::Repeat($S,$Times)
}

<#
.SYNOPSIS
    Improved version of Out-File that generate new name for the output file
    instead of overwriting an existing file.
#>
Function Out-FileX()
{
    [CmdletBinding()]
    [OutputType([String])]
    param(
        [Parameter(Mandatory = $true)] [String]$FilePath
    )
    $p = $FilePath
    $i = 1
    while (Test-Path $p) {
        $itemInPath = Get-Item -Path $p
        $p = $itemInPath.DirectoryName + "\" + $itemInPath.BaseName + "($i)" + $itemInPath.Extension
        $i += 1
    }
    Out-File -FilePath $p -InputObject
}

#endregion

#region Security

<#
.SYNOPSIS
    Confirm precense and validity of Authenticode signatures within directory
#>
Function Confirm-Signatures
{
    [CmdletBinding()]
    param(
        # Directory to check
        $FolderPath,
        # Recursion depth (0=no recursion)
        [int]$Depth = 1,
        # Check signatures of PowerShell files
        [bool]$IncludePSFiles
    )
    [System.IO.DirectoryInfo]$Folder = AsFileObject $FolderPath $true
    if($Folder)
    {
        $baseExtension = @(
            '*.exe', '*.dll', '*.sys', '*.ocx', # binary code
            '*.msi', '*.msu', '*.cab', '*.appx', # installation packages
            '*.appxbundle')
        $psExtensions = switch ($IncludePSFiles) {
            $true { @('*.ps1', '*.psm1', '*.psd1', '*.ps1xml', '*.psc1') }
            $false { @() }
        }
        $extensions = $baseExtension,$psExtensions
        # NOTE: For unknown reason ForEach-Object must be passed list of files
        # through pipelining, i.e. saving output of Get-ChildItem does not work
        # properly
        # NOTE: ForEach is Select from LINQ perspective: it produces output entities
        $signatures = Get-ChildItem -Path $Folder -Include $extensions -Depth $Depth -Force |
            ForEach-Object { Get-AuthenticodeSignature $_ } |
            Select-Object -Property Path,Status,IsOSBinary # needed to get rid of grouping by subdirectory
        # NOTE: [System.Enum]::GetValues([System.Management.Automation.SignatureStatus]) to see all
        $validSignatures = $signatures | Where-Object { $_.Status -eq [SignatureStatus]::Valid }
        $unverifiableFiles = $signatures | Where-Object { $_.Status -in @([SignatureStatus]::NotSigned,
            [SignatureStatus]::NotTrusted) }
        $compromisedFiles = $signatures | Where-Object { $_.Status -eq [SignatureStatus]::HashMismatch }
        $fOutput = @{
            Property= @('Path','Status','IsOSBinary')
        }
        $validSignatures | Format-Table @fOutput
        $unverifiableFiles | Format-Table @fOutput
        $compromisedFiles | Format-Table @fOutput
    }
}

<#
.SYNOPSIS
    Get password input from the interactive user and hash it.
#>
Function PasswordInputAsHash
{
    [CmdletBinding()]
    param(
        $Algorithm = 'SHA1',
        [int]$CharRangeStart = 33,
        [int]$CharRangeEnd = 126
    )
    $mStream = [System.IO.MemoryStream]::new()
    $sWriter = [System.IO.StreamWriter]::new($mStream)
    do {
        $k = [System.Console]::ReadKey($true)
        if(([int]$k.KeyChar -ge $CharRangeStart) -and ([int]$k.KeyChar -le $CharRangeEnd)){
            $sWriter.Write($k.KeyChar)
            $sWriter.Flush()
        }
    } while (
        $k.Key -ne ([System.ConsoleKey]::Enter)
    )
    $mStream.Position = 0
    $hash = (Get-FileHash -Algorithm $Algorithm -InputStream $mStream).Hash
    $sWriter.Close()
    return $hash
}

#endregion

#region System

<#
.SYNOPSIS
    Add values to environment variable Path.
.NOTES
    Deleting values from path may be added later.
#>
Function Edit-Path
{
    [CmdletBinding()]
    [OutputType([String])]
    Param(
        [Parameter(Mandatory=$false)] [String]$Add,
        [Parameter(Mandatory=$false)] [Switch]$Get,
        [Parameter(Mandatory=$false)] [Switch]$Global,
        [Parameter(Mandatory=$false)] [Switch]$Subdirectories
    )
    if(!$Add -and !$Get)
    {
        Write-Host "No request received"
        return
    }
    $scope = If($Global) {
        'Machine'
    } else { [EnvironmentVariableTarget]::User } # Value is simply 'User'

    # Elevator
    $currentUser = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    $adminRole = [Security.Principal.WindowsBuiltInRole]::Administrator
    if ($Add -and $Global -and !($currentUser.IsInRole($adminRole)))
    {
        $discard, $invokeParams = $MyInvocation.Line -Split '.ps1 ',2,"SimpleMatch" # Split is different from .NET
        $thisCommand = "&{$PSCommandPath $invokeParams}" # -File method of starting ..
        $psArguments = @("-NoProfile",
            "-ExecutionPolicy", "RemoteSigned",
            "-Command", "`"$thisCommand`""
        )
        Start-Process -FilePath PowerShell -Verb RunAs -Wait`
            -WorkingDirectory $pwd`
            -ArgumentList $psArguments
    }
    else {
        $KeyLocation = If($Global) {
            'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment'
        } else {
            'HKEY_CURRENT_USER\Environment'
        }

        function append($addPath) # $addPath defined within this nested function is not really necessary
        {
            $existingValues = (Get-ItemProperty -Path ('Registry::' + $KeyLocation) -Name PATH).path
            # Do not use $env:Path because it combines both Machine and User scope!
            $envPath = [System.Environment]::GetEnvironmentVariable("Path", $scope)
            $existingValuesArray = ($envPath) -split ';'
            if (-Not($existingValuesArray -Contains "$addPath")) {
                $newValue = "$existingValues$addPath;" # there must be semicolon after the last path
                Set-ItemProperty -Path ('Registry::' + $KeyLocation) -Name PATH -Value "$newValue"
                write-verbose "Added $addPath."
            }
            else { write-verbose "Skipping $addPath because value already exists."}
        }

        append($Add) # invoke function defined above
        if ($Subdirectories) {
            $subs = Get-ChildItem -Path $Add -Recurse -Directory -Force | Select-Object FullName
            if ($subs.Count -le 5) {
                foreach ($sub in $subs) {
                    write-verbose "Added $sub."
                    append($sub)
                }
            }
            else { write-error "Too many subdirectories to add." }
        }
        write-verbose "Path:`n" $env:Path.Replace(';', "`n")
    }

    if($Get){
        return [System.Environment]::GetEnvironmentVariable("Path", $scope)
    }
}

<#
.SYNOPSIS
    Input type enum for Get-SystemFeature
#>
enum SystemFeature
{
    Capabilities = 1 # 0b00000001
    Devices = 2 # 0b00000010
    OptionalFeatures = 4 # 0b00000100
    Services = 8 # 0b00001000
    StoreApps = 16 # 0b00001000
}

<#
.SYNOPSIS
    Display installed system features. Listings are filtered extensively compared
    to raw output in order to display only the most relevant information (system-specific
    features that have been explicitly set up.)
#>
Function Get-SystemFeature
{
    [CmdletBinding()]
    param(
        # Possible values: Capabilities, Devices, OptionalFeatures, Services, StoreApps
        [Parameter(Mandatory = $true)] [SystemFeature]$Feature
        #[Parameter(Mandatory = $false)] [Switch]$Capabilities,
        #[Parameter(Mandatory = $false)] [Switch]$Services
    )
    $output = $false
    Switch($Feature)
    {
        Capabilities{
            $output = Get-WindowsCapability -Online | Where-Object { $_.State -eq "Installed" }
            $output | Format-Table @{
                Label = "Identifier"
                Expression = { ($_.Name -split '~',2,"SimpleMatch")[0].TrimEnd('~') }
                }
        }
        Devices{
            $output = Get-PnpDevice -PresentOnly | Where-Object { $_.Manufacturer -ne "Microsoft" }`
            | Where-Object { $_.Manufacturer -notlike "Intel*" }`
            | Where-Object { $_.Manufacturer -notlike "Generic*" }`
            | Where-Object { $_.Manufacturer -notlike "(*)" }
            $output | Format-Table Name,Manufacturer,Service
        }
        OptionalFeatures{
            $output = Get-WindowsOptionalFeature -Online | Where-Object { $_.State -eq "Enabled" }
            $output | Format-Table @{
                Label = "Identifier"
                Expression = { $_.FeatureName }
                }
        }
        Services{
            $excludeProducts = @(
                "Microsoft® Windows® Operating System",
                "Windows® Search",
                "Microsoft OneDrive",
                "Microsoft Edge",
                "Microsoft Edge Update",
                "Microsoft 365 and Office"
            )
            $allServices = Get-WmiObject win32_service
            $preOutput = $allServices `
                | Where-Object { $_.StartMode -ne "Disabled" }`
                | Where-Object { $_.PathName -notlike "C:\Windows\system32\svchost.exe*" } `
                | Where-Object { $_.PathName -notlike "C:\Windows\system32\lsass.exe*" } `
                | Where-Object { $_.PathName -notlike "C:\Windows\System32\DriverStore\*" } `
                | Select-Object -Property DisplayName,StartMode,PathName,
                    @{ Label="ExecutablePath"; Expression={ ($_.PathName -split '.exe',2,"SimpleMatch")[0].TrimStart('"') + ".exe"} }`
                | Select-Object -Property DisplayName,StartMode,PathName,ExecutablePath,
                    @{ Label="ExecutableImage"; Expression={ (Get-ChildItem $_.ExecutablePath)[0] } }
            $output = $preOutput | Select-Object -Property DisplayName,StartMode,PathName,ExecutablePath,
                @{ Label = "Company"; Expression = { $_.ExecutableImage.VersionInfo.CompanyName } },
                @{ Label = "Product"; Expression = { $_.ExecutableImage.VersionInfo.ProductName } } `
                | Where-Object { $_.Product -notin $excludeProducts }
            Write-Host "Services excluding OS and system devices`r`n"
            $output | Format-Table @{ Label = "Identifier"; Width=40; Expression = { $_.DisplayName } },
                @{ Label = "Start Mode"; Width=12; Expression = { $_.StartMode } },
                @{ Label = "Company"; Width=25; Expression = { $_.Company } },
                @{ Label = "Product"; Width=40; Expression = { $_.Product } },
                @{ Label = "Path"; Expression = { $_.ExecutablePath } }
            Write-Host "Disabled Services`r`n"
            $allServices | Where-Object { $_.StartMode -eq "Disabled" } `
                | Format-Table @{ Label = "Identifier"; Width=40; Expression = { $_.DisplayName } },
                @{ Label = "Start Mode"; Width=12; Expression = { $_.StartMode } },
                @{ Label = "Path"; Expression = { $_.PathName } }
        }
        StoreApps{
            $systemPackages = Get-AppxPackage -AllUsers -PackageTypeFilter Main,Bundle
            $userPackages = Get-AppxPackage -PackageTypeFilter Main,Bundle
            $output = $systemPackages + $userPackages | Where-Object { ($_.Name -notlike "Microsoft.Windows*") }`
                | Where-Object { ($_.Name -notlike "Microsoft.MicrosoftEdge*") }`
                | Where-Object { $_.Publisher -notlike "CN=Microsoft Windows*" }
            $output | Select-Object -Property Name,Version -Unique | Format-Table
        }
    }
    # NOTE: State is not string but enum PackageFeatureState. Despite this, comparison
    # with string is possible.
}

<#
.SYNOPSIS
    Install OpenType, Type1 or TrueType font
#>
Function Install-Font
{
    [CmdletBinding()]
    param(
        $FontFile,
        [Switch]$CurrentUser
    )
    [System.IO.FileInfo]$File = AsFileObject $FontFile
    $folderItem = (New-Object -ComObject 'Shell.Application').NameSpace($File.Directory.FullName).
        ParseName($File.Name)
    $verbTitle = if($CurrentUser) {'Install'} else { 'Install for &all users' }
    # NOTE: Verbs() returns enumerator that can be consumed by ForEach but it is not an array
    # that could be accessed by index
    $folderItem.Verbs() | ForEach-Object { if( $_.Name -eq $verbTitle ) {$_.DoIt()} }
}

<#
.SYNOPSIS
    Install OpenType, Type1 and TrueType fonts within given folder and its subfolders
#>
Function Install-Fonts
{
    [CmdletBinding()]
    param(
        $FolderPath,
        [Switch]$CurrentUser
    )
    [System.IO.DirectoryInfo]$Folder = AsFileObject $FolderPath $true
    if($Folder)
    {
        # NOTE: For unknown reason ForEach-Object must be passed list of files
        # through pipelining, i.e. saving output of Get-ChildItem does not work
        # properly
        Get-ChildItem $Folder -Include @('*.ttf', '*.otf', '*.pfm') -File -Recurse |
        ForEach-Object { Install-Font -FontFile $_ -CurrentUser:$CurrentUser }
    }
}

#endregion