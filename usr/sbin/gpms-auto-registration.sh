#!/bin/bash

#
# Automatic GPMS registration script 
#  written by Gooroom Project Team <shjung@gooroom.kr>
#

if [ $ENABLE_AUTO_REGI != 'Yes' ] 
then
        exit 0
fi

if [ ! -z $NICDEV ]
then
	
	CLIENT_NAME=`ip address show $NICDEV | grep inet | head -1 | awk  '{print $2}' | awk -F "/" '{print $1}'`
fi

if [ -z $CLIENT_NAME ] || [ -z $GKM_SERVER ] || [ -z $REG_KEY ]
then
        echo Configuration is not properly set
	echo $GKM_SERVER >> /tmp/gpms_autoregi_debug.txt
	echo $REG_KEY >> /tmp/gpms_autoregi_debug.txt
	echo $CLIENT_NAME >> /tmp/gpms_autoregi_debug.txt
        exit 1
fi

systemctl start gooroom-agent
sleep 1
if ( dbus-send --system --print-reply --type=method_call --dest='kr.gooroom.agent' '/kr/gooroom/agent' kr.gooroom.agent.do_task string:'{"module" : {"module_name" : "SERVER","task" : {"task_name" : "grm_heartbit","in" : {}}}}' | grep "\"status\"\:\ \"200\"" )
#if ( ! true  ) 
then
	echo gpms-server is already connected.
else
	systemctl stop gooroom-agent
	DO="yes"
	while [ $DO == "yes"  ]
	do
		
		if (gooroom-client-server-register noninteractive-regkey -d $GKM_SERVER -m $CLIENT_NAME -u "AUTO_REGED" -k $REG_KEY -r 2 )
		then
			DO="no"	
		fi
	done
	sleep 1
	systemctl restart gooroom-agent
fi
