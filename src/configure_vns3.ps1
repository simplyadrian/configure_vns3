# Powershell 2.0

if($env:RS_REBOOT){exit 0}

# Stop and fail script when a command fails.
$errorActionPreference = "Stop"

$vns3api = "c:\cft\vns3api"
$HELPER_SCRIPTS_HOME = "c:\cft\helpers"
$clientPackUserName = $env:API_USER_NAME
$clientPackPassword = $env:API_PASSWORD
$manager1 = $env:MANAGER_1
$manager2 = $env:MANAGER_2
$key_manager = $env:KEY_MANAGER
$OPENVPN_CONFIG_DIR = "C:\Program Files\OpenVPN\config\"

# Test for OpenVPN installation
sc.exe query OpenVPNService

# Install required ruby gem
C:\Ruby200-x64\bin\gem install json_pure

$tempbool = $?

If ($tempbool -eq   [System.Convert]::ToBoolean("$false"))
{
 echo "OpenVPN not installed/configured properly"
 echo "Cannot Configure VNS3 - exiting"
 exit
}

$SCRIPT_HOME = "c:\cft"
if(!(Test-Path $SCRIPT_HOME))
  {
   mkdir $SCRIPT_HOME
  }
else
  {
   Write-Host "$SCRIPT_HOME already exists"
  }

if(!(Test-Path $vns3api))
  {
   mkdir $vns3api
  }
else
  {
   Write-Host "$vns3api already exists"
  }

if(!(Test-Path $HELPER_SCRIPTS_HOME))
  {
   mkdir $HELPER_SCRIPTS_HOME
  }
else
  {
   Write-Host "$HELPER_SCRIPTS_HOME already exists"
  }

# Copy in attachments for this rightscript
cd $env:RS_ATTACH_DIR
cp 7za.exe $HELPER_SCRIPTS_HOME\
cp vnscubed.rb $vns3api\
cp api.rb $vns3api\

# Get next vailable vns3 address; api call locks the client pack and returns name for fetching
echo "got to first ruby  call"
$clientpackinfo = $SCRIPT_HOME + "\clientpackname.txt"
C:\Ruby200-x64\bin\ruby.exe  $vns3api\vnscubed.rb -K $clientPackUserName -S $clientPackPassword -H $key_manager get_next_available_clientpack > $clientpackinfo

$myCubeAddress = get-content $clientpackinfo | select-string "name"
$myCubeAddress  = [regex]::Split($myCubeAddress, "name: ")
$myCubeAddress = ("$myCubeAddress").Trim()

$myCubeClientPack = $myCubeAddress + ".zip"
echo $myCubeClientPack

cd $SCRIPT_HOME

# Get client pack file from keymanager (you use one of your vns3 managers as the central key manager

$clientpack_outputfile = $myCubeClientPack
C:\Ruby200-x64\bin\ruby.exe  $vns3api\vnscubed.rb -K $clientPackUserName -S $clientPackPassword -H $key_manager fetch_clientpack  --name $myCubeAddress --format "zip" -o $clientpack_outputfile

If ($tempbool -eq   [System.Convert]::ToBoolean("$false"))
{
 echo "Could not retrieve $myCubeClientPack"
 echo "Cannot Configure VNS3 "
 exit

}

# Remove any previous vnscubed configurations
# and add new ones from client pack
echo "saving clientpack"
cd $OPENVPN_CONFIG_DIR
remove-item -path $OPENVPN_CONFIG_DIR* -recurse  -force

cd $SCRIPT_HOME
echo "unpacking $clientpack_outputfile"
c:\cft\helpers\7za.exe e -y -oc:\cft\results\ *.zip
echo "copying configuration files to $OPENVPN_CONFIG_DIR"
cp $SCRIPT_HOME\results\* $OPENVPN_CONFIG_DIR\

cd $OPENVPN_CONFIG_DIR
# Append VNS3 manager information to the OpenVPN configuration
echo "adding sleep command to allow the OpenVPNService to come up before starting the tunnel"
Get-Content vnscubed.conf | %{$_ -replace "explicit-exit-notify 5","explicit-exit-notify `r`ntap-sleep 3"} | Set-Content vnscubed.conf1 -force
    
echo "VNS3 Config file is: vnscubed.conf and appending remote managers to the same"
add-content vnscubed.conf1 "remote $manager1 1194"
add-content vnscubed.conf1 "remote $manager2 1194"

echo "renaming vnscubed.conf to vnscubed.ovpn"
Rename-Item vnscubed.conf1 vnscubed.ovpn
Remove-Item vnscubed.conf

# Set RS_VNS3_CLIENT_PACK_NAME environment variable 
Write-Host "Setting RS_VNS3_CLIENT_PACK_NAME environment variable to '$myCubeAddress'..."
[environment]::SetEnvironmentVariable("RS_VNS3_CLIENT_PACK_NAME", "$myCubeAddress", "Machine")
