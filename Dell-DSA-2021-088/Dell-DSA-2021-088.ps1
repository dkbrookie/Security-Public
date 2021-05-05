$userFolders = Get-ChildItem "$env:SystemDrive\Users"
$ErrorActionPreference = 'Stop'
ForEach ($user in $userFolders) {
    $path = "$env:SystemDrive\Users\" + $user.Name + "\AppData\Local\Temp\dbutil_2_3.sys"
    If ((Test-Path -Path $path -PathType Leaf)) {
        Try {
            Remove-Item $path -Force
            If ($status -ne 'Failed') {
                $status = 'Success'
            }
        } Catch {
            $status = 'Failed'
        }
    } Else {
        $status = 'Success'
    }
}


Try {
    If ((Test-Path -Path "$env:SystemDrive\Temp\dbutil_2_3.sys" -PathType Leaf)) {
        Remove-Item "$env:SystemDrive\Temp\dbutil_2_3.sys" -Force
        If ($status -ne 'Failed') {
            $status = 'Success'
        }
    }
} Catch {
    $status = 'Failed'
}


If ($status -eq 'Success') {
    "!Success: Successfully removed dbutil_2_3.sys from all user folders and C:\Temp"
} Else {
    "!Failed: Failed to remove dbutil_2_3.sys from all user folders and C:\Temp. Full error output: $Error"
}