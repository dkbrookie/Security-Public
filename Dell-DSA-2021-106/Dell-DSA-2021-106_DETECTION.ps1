﻿# Affected models and minimum BIOS versions to be considered safe. Anything lower is vulnerable.
$affectedModels = @{
    "Alienware m15 R6" = "1.3.3";
    "ChengMing 3990" = "1.4.1";
    "ChengMing 3991" = "1.4.1";
    "Dell G15 5510" = "1.4.0";
    "Dell G15 5511" = "1.3.3";
    "Dell G3 3500" = "1.9.0";
    "Dell G5 5500" = "1.9.0";
    "Dell G7 7500" = "1.9.0";
    "Dell G7 7700" = "1.9.0";
    "Inspiron 14 5418" = "2.1.0 A06";
    "Inspiron 15 5518" = "2.1.0 A06";
    "Inspiron 15 7510" = "1.0.4";
    "Inspiron 3501" = "1.6.0";
    "Inspiron 3880" = "1.4.1";
    "Inspiron 3881" = "1.4.1";
    "Inspiron 3891" = "1.0.11";
    "Inspiron 5300" = "1.7.1";
    "Inspiron 5301" = "1.8.1";
    "Inspiron 5310" = "2.1.0";
    "Inspiron 5400 2n1" = "1.7.0";
    "Inspiron 5400 AIO" = "1.4.0";
    "Inspiron 5401" = "1.7.2";
    "Inspiron 5401 AIO" = "1.4.0";
    "Inspiron 5402" = "1.5.1";
    "Inspiron 5406 2n1" = "1.5.1";
    "Inspiron 5408" = "1.7.2";
    "Inspiron 5409" = "1.5.1";
    "Inspiron 5410 2-in-1" = "2.1.0";
    "Inspiron 5501" = "1.7.2";
    "Inspiron 5502" = "1.5.1";
    "Inspiron 5508" = "1.7.2";
    "Inspiron 5509" = "1.5.1";
    "Inspiron 7300" = "1.8.1";
    "Inspiron 7300 2n1" = "1.3.0";
    "Inspiron 7306 2n1" = "1.5.1";
    "Inspiron 7400" = "1.8.1";
    "Inspiron 7500" = "1.8.0";
    "Inspiron 7500 2n1 - Black" = "1.3.0";
    "Inspiron 7500 2n1 - Silver" = "1.3.0";
    "Inspiron 7501" = "1.8.0";
    "Inspiron 7506 2n1" = "1.5.1";
    "Inspiron 7610" = "1.0.4";
    "Inspiron 7700 AIO" = "1.4.0";
    "Inspiron 7706 2n1" = "1.5.1";
    "Latitude 3120" = "1.1.0";
    "Latitude 3320" = "1.4.0";
    "Latitude 3410" = "1.9.0";
    "Latitude 3420" = "1.8.0";
    "Latitude 3510" = "1.9.0";
    "Latitude 3520" = "1.8.0";
    "Latitude 5310" = "1.7.0";
    "Latitude 5310 2 in 1" = "1.7.0";
    "Latitude 5320" = "1.7.1";
    "Latitude 5320 2-in-1" = "1.7.1";
    "Latitude 5410" = "1.6.0";
    "Latitude 5411" = "1.6.0";
    "Latitude 5420" = "1.8.0";
    "Latitude 5510" = "1.6.0";
    "Latitude 5511" = "1.6.0";
    "Latitude 5520" = "1.7.1";
    "Latitude 5521" = "1.3.0 A03";
    "Latitude 7210 2-in-1" = "1.7.0";
    "Latitude 7310" = "1.7.0";
    "Latitude 7320" = "1.7.1";
    "Latitude 7320 Detachable" = "1.4.0 A04";
    "Latitude 7410" = "1.7.0";
    "Latitude 7420" = "1.7.1";
    "Latitude 7520" = "1.7.1";
    "Latitude 9410" = "1.7.0";
    "Latitude 9420" = "1.4.1";
    "Latitude 9510" = "1.6.0";
    "Latitude 9520" = "1.5.2";
    "Latitude 5421" = "1.3.0 A03";
    "OptiPlex 3080" = "2.1.1";
    "OptiPlex 3090 UFF" = "1.2.0";
    "OptiPlex 3280 All-in-One" = "1.7.0";
    "OptiPlex 5080" = "1.4.0";
    "OptiPlex 5090 Tower" = "1.1.35";
    "OptiPlex 5490 AIO" = "1.3.0";
    "OptiPlex 7080" = "1.4.0";
    "OptiPlex 7090 Tower" = "1.1.35";
    "OptiPlex 7090 UFF" = "1.2.0";
    "OptiPlex 7480 All-in-One" = "1.7.0";
    "OptiPlex 7490 All-in-One" = "1.3.0";
    "OptiPlex 7780 All-in-One" = "1.7.0";
    "Precision 17 M5750" = "1.8.2";
    "Precision 3440" = "1.4.0";
    "Precision 3450" = "1.1.35";
    "Precision 3550" = "1.6.0";
    "Precision 3551" = "1.6.0";
    "Precision 3560" = "1.7.1";
    "Precision 3561" = "1.3.0 A03";
    "Precision 3640" = "1.6.2";
    "Precision 3650 MT" = "1.2.0";
    "Precision 5550" = "1.8.1";
    "Precision 5560" = "1.3.2";
    "Precision 5760" = "1.1.3";
    "Precision 7550" = "1.8.0";
    "Precision 7560" = "1.1.2";
    "Precision 7750" = "1.8.0";
    "Precision 7760" = "1.1.2";
    "Vostro 14 5410" = "2.1.0 A06";
    "Vostro 15 5510" = "2.1.0 A06";
    "Vostro 15 7510" = "1.0.4";
    "Vostro 3400" = "1.6.0";
    "Vostro 3500" = "1.6.0";
    "Vostro 3501" = "1.6.0";
    "Vostro 3681" = "2.4.0";
    "Vostro 3690" = "1.0.11";
    "Vostro 3881" = "2.4.0";
    "Vostro 3888" = "2.4.0";
    "Vostro 3890" = "1.0.11";
    "Vostro 5300" = "1.7.1";
    "Vostro 5301" = "1.8.1";
    "Vostro 5310" = "2.1.0";
    "Vostro 5401" = "1.7.2";
    "Vostro 5402" = "1.5.1";
    "Vostro 5501" = "1.7.2";
    "Vostro 5502" = "1.5.1";
    "Vostro 5880" = "1.4.0";
    "Vostro 5890" = "1.0.11";
    "Vostro 7500" = "1.8.0";
    "XPS  13 9305" = "1.0.8";
    "XPS 13 2in1  9310" = "2.3.3";
    "XPS 13 9310" = "3.0.0";
    "XPS 15 9500" = "1.8.1";
    "XPS 15 9510" = "1.3.2";
    "XPS 17 9700" = "1.8.2";
    "XPS 17 9710" = "1.1.3";
}

[array]$outputLog = @()

$currentBiosVersion = (Get-WmiObject -ClassName Win32_BIOS).SMBIOSBIOSVersion
$modelName = (Get-WmiObject -ClassName Win32_ComputerSystem).Model

If (!$affectedModels.Contains($modelName)) {
    $outputLog += "!Warning: Exiting Script. This model is not in the affected models list. It is likely that this machine is not vulnerable to the DSA-2021-016 vulnerability. Check your search. The model is $modelName. If there is any question, please check the list on Dell's site to confirm. https://www.dell.com/support/kbdoc/en-us/000188682/dsa-2021-106-dell-client-platform-security-update-for-multiple-vulnerabilities-in-the-supportassist-biosconnect-feature-and-https-boot-feature"
    Write-Output "protected=1|outputLog=$outputLog"
    Return
}

$minimumSafeBiosVersion = $affectedModels[$modelName]

# Don't know how to compare these models with A0 in the version yet. Powershell doesn't compare these properly, though I assume
# there's some way to handle it. Not putting energy into it yet, because we don't currently manage any of the affected models.
If ($minimumSafeBiosVersion -like "*A0*") {
    $outputLog += "!Failed: Exiting Script. This model is not currently supported by the script. This machine needs to be updated manually, or the script needs to be updated to support it."
    Write-Output "protected=0|outputLog=$outputLog"
    Return
}

# If current bios version is smaller than minimum safe BIOS version
If ($currentBiosVersion -lt $minimumSafeBiosVersion) {
    $outputLog += "!Failed: This machine is an affected model and doesn't meet the minimum BIOS version requirement. BIOS Version: $currentBiosVersion. BIOS version needed: $minimumSafeBiosVersion or higher"
    $protected = 0
} Else {
    $outputLog += "!Success: This model is in the affected models list, but it meets the minimum BIOS version requirement. This machine is not vulnerable and no update is needed."
    $protected = 1
}

Write-Output "protected=$protected|outputLog=$outputLog"
