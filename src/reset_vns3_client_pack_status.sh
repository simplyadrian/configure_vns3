#!/bin/bash

#
# Test for a reboot,  if this is a reboot just skip this script.
#
if test "$RS_REBOOT" = "true" -o "$RS_ALREADY_RUN" = "true" ; then
  logger -t RightScale "SYS Reset VNS3 Client Pack Status (linux),  skipped on a reboot."
  exit 0
fi

SCRIPT_HOME=$SCRIPT_HOME
myCubeAddress=$(cat ${SCRIPT_HOME}/clientpackinfo.txt | sed -n 's/name://p')

ruby $VNS3API/vnscubed.rb -K $API_USER_NAME -S $API_PASSWORD -H $KEY_MANAGER edit_clientpack --name $myCubeAddress --enabled true --checked_out false
