#!/bin/bash

#
# Test for a reboot,  if this is a reboot just skip this script.
#
if test "$RS_REBOOT" = "true" -o "$RS_ALREADY_RUN" = "true" ; then
  logger -t RightScale "VNS3 Install,  skipped on a reboot."
  exit 0
fi

echo 'creating $SCRIPT_HOME directory'
if [ ! -d "$SCRIPT_HOME" ]; then
   mkdir $SCRIPT_HOME
else
   echo '$SCRIPT_HOME already exists'
   logger -t RightScale '$SCRIPT_HOME already exists'
fi

echo 'creating $vns3api directory'
if [ ! -d "$VNS3API" ]; then
   mkdir $VNS3API
else
   echo '$VNS3API already exists'
   logger -t RightScale '$vns3api already exists'
fi

# Copy in attachments for this rightscript
cp $RS_ATTACH_DIR/vnscubed.rb $VNS3API/
cp $RS_ATTACH_DIR/api.rb $VNS3API/

# Get next vailable vns3 address; api call locks the client pack and returns name for fetching
echo 'performing get_next_available_clientpack action and pushing results to $clientpackinfo'
ruby  $VNS3API/vnscubed.rb -K $API_USER_NAME -S $API_PASSWORD -H $KEY_MANAGER desc_clientpacks --sort true | grep -E '(name|checked_out|enabled):' | grep -A 2 '$VNS3_SUBNET' | grep -A 2 'checked_out: false' | grep -v -- '--' > > $SCRIPT_HOME/clientpackinfo.txt

myCubeAddress=$(cat ${SCRIPT_HOME}/clientpackinfo.txt | head -n 2 | sed -n 's/name://p' | tr -d "'")
echo $myCubeAddress

myCubeClientPack=$myCubeAddress.tar.gz
echo $myCubeClientPack

# Get client pack file from keymanager (you use one of your vns3 managers as the central key manager

clientpack_outputfile=$myCubeClientPack
ruby $VNS3API/vnscubed.rb -K $API_USER_NAME -S $API_PASSWORD -H $KEY_MANAGER fetch_clientpack  --name $myCubeAddress --format "tarball" -o $clientpack_outputfile

if [ $? -eq 1 ]; then
 echo 'Could not retrieve $myCubeClientPack'
 echo 'Cannot Configure VNS3'
 exit 1
fi

ruby $VNS3API/vnscubed.rb -K $API_USER_NAME -S $API_PASSWORD -H $KEY_MANAGER edit_clientpack --name $myCubeAddress --enabled true --checked_out true 

# Remove any previous vnscubed configurations
# and add new ones from client pack
#echo 'saving clientpack'
rm -Rf $OPENVPN_CONFIG_DIR/*

echo 'unpacking $clientpack_outputfile'
tar xvfz $myCubeClientPack -C $OPENVPN_CONFIG_DIR/
if [ $? -eq 0 ]; then
  echo 'VNS3 client unpacking done'
else
  echo 'VNS3 client unpacking failed. Aborting installation!'
    logger -t RightScale 'VPN-Cubed client unpacking failed. Aborting installation!'
  exit 1
fi

echo "remote $MANAGER_1 1194" >> $OPENVPN_CONFIG_DIR/vnscubed.conf
echo "remote $MANAGER_2 1194" >> $OPENVPN_CONFIG_DIR/vnscubed.conf

service openvpn start

logger -t RightScale 'Installed the VNS3 client for this server.'

# sleep for 30 seconds while the interface comes up
sleep 30

# make sure openvpn is set to start upon reboot
chkconfig openvpn on

exit 0
