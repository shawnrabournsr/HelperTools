<#
    This script extracts the WinRE.wim file out of a Windows Server installation media DVD
    
    ***Note: It assumes the DVD is mounted on drive D: (so be sure to mount it first! :-)  )
    
    Steps: 
    - Mount D:\sources\install.wim to c:\Mount\Windows
    - xCopy WinRE.wim from the mount to the proper Cache folder for RMAD to use.
    - clean up by Unmounting install.wim 

    WinRE.wim is needed for Bare Metal recovery. 
    We use WinRE as a foundation for the Quest Recovery Environment .iso files, 
    We create these .iso's when you run verify settings or Start recovery of a project where the 
    Bare Metal Recovery method is selected.
    Normally the FRC will extract WinRE.wim from the backup, but there are occassions where this file 
    either doesn't exist, or otherwise cannot be used.  This script caches a master copy for use. 
 
#>

# Set some variables
#  Note: if you had to mount a .iso of the Windows Server media, 
#  then be sure the $InstallwimPath is correct! 
$WinMountPath = "C:\mount\Windows" # <-- Script will create this directory if it doesn't exist. 
$InstallwimPath = "D:\sources\install.wim" # <-- this is the expected location if using a DVD
$CacheDir = "C:\ProgramData\Quest\Recovery Manager for Active Directory\Cache\WinRE\10.0" # <-- Default

write-host -ForegroundColor Green "Beginning WinRE.wim extraction"
write-host -ForegroundColor Cyan  "Note: Errors that say 'already exists' can be ignored"
C:
cd \
Get-Date

# Mount Install.wim Windows Image. 
write-host -ForegroundColor Cyan "Mounting Server Windows image (Install.wim)"
md $WinMountPath
Mount-WindowsImage -ImagePath $InstallWimPath -Index 1 -path $WinMountPath -ReadOnly
 
# Copy the winre.wim file out & unhide it
Get-Date
write-host -ForegroundColor Cyan "Copying winre.wim out to RMAD Cache location"
md $CacheDir
cd $CacheDir
$WinREwimPath = $WinMountPath + "\windows\System32\Recovery\winre.wim"
xcopy /H $WinREwimPath .
write-host -ForegroundColor Cyan "Unhiding WinRE.wim so it can be used"
attrib -h -s winre.wim
 
# Discard the Install.wim Windows Server image 
Get-Date
write-host -ForegroundColor Cyan "Cleaning up..."
cd \
Get-Date 
write-host -ForegroundColor Cyan "Dismounting Windows image"
Dismount-WindowsImage -path: "c:\mount\windows" -Discard
Get-Date
write-host -ForegroundColor green "Done...!"
