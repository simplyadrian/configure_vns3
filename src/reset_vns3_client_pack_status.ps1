# Powershell 2.0

if($env:RS_REBOOT){exit 0}

# Stop and fail script when a command fails.
$errorActionPreference = "Stop"

# load library functions
$rsLibDstDirPath = "$env:rs_sandbox_home\RightScript\lib"
. "$rsLibDstDirPath\tools\PsOutput.ps1"
. "$rsLibDstDirPath\tools\Checks.ps1"
. "$rsLibDstDirPath\tools\ResolveError.ps1"

$vns3api = "c:\cft\vns3api"

try
{
  C:\Ruby200-x64\bin\ruby.exe $vns3api\vnscubed.rb -K api -S $env:API_PASSWORD -H $env:KEY_MANAGER edit_clientpack --name $env:RS_VNS3_CLIENT_PACK_NAME --enabled true --checked_out false
}
catch
{
    ResolveError
    exit 1
}
