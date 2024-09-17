#!/bin/bash

echo "hello, Starting the Assertion"

user=$1
source_ip=$2

echo "User: $user"
echo "Source IP: $source_ip"
ip_address=$(curl -s ifconfig.me)
echo "Machine IP: $ip_address"
string=$(groups $USER)
prefix="$USER : "
groupsStr=${string#"$prefix"}

hoststr=$(hostname -f)
prefixhost="Static hostname: "
hostname=${hoststr#"$prefixhost"}

input=$(tail -100 /var/log/auth.log | grep -oP '(?<=Postponed publickey for )\w+' | tail -1)

value=$(id -Gn $user)

# Get the user ID of the specified username
userId=$(id -u $user)
echo "User ID: $userId"

# Determine credential type based on user ID range
if [[ $userId -ge 1 && $userId -le 999 ]]; then
  credentialType="ServiceAccount"
else
  credentialType="SSH"
fi
echo "Credential Type: $credentialType"

# Note: need to replace the placeholders with actual values
ldapServer=""
searchBase=""
bindDN=""
bindPassword=""

# Fetching OU of the machine
ou=$(ldapsearch -x -H "$ldapServer" -D "$bindDN" -w "$bindPassword" -b "$searchBase" "(cn=$hostname)" ou | grep ou: | sed 's/ou: //')

# Fetching AD ID of the machine
adId=$(ldapsearch -x -H "$ldapServer" -D "$bindDN" -w "$bindPassword" -b "$searchBase" "(cn=$hostname)" objectGUID | grep objectGUID: | sed 's/objectGUID: //')
# Check if user is a local user
if getent passwd "$user" > /dev/null 2>&1; then
    usertype="local"
else
ldapsearchResult=$(ldapsearch -x -H "$ldapServer" -D "$bindDN" -w "$bindPassword" -b "$searchBase" "(uid=$user)" | grep "dn:")

    if [ -n "$ldapsearchResult" ]; then
        usertype="AD"
    else
        usertype="unknown"
    fi
fi

echo "OU: $ou"
echo "AD ID: $adId"
uuid=$(uuidgen)
echo $uuid

generate_post_data() {
  cat <<EOF
{
  "username": "$(echo ${user})",
  "credentialType": "AD",
  "hostname": "$(echo ${hoststr})",
  "groupName": "CN=Domain Admins,CN=Users,DC=authull3,DC=com",
  "orgId": 105,
  "tenantId": 1,
  "requestId": "$(echo $uuid)",
  "sourceIp": "$(echo ${source_ip})",
  "ou": "${ou}",
  "adId": "${adId}",
  "usertype":"AD"
}
EOF
}

echo $(generate_post_data)

echo "Script executed from: ${PWD}"
echo "First arg is $1"

RES=$(curl -H "Accept: application/json" -H "Content-Type:application/json" --connect-timeout 50 -m 50 -X POST --data "$(generate_post_data)"  "https://prod.api.authnull.com/authnull0/api/v1/authn/v3/do-authenticationV4")
SSO=$(echo "$RES" | jq -r '.ssoUrl')
requestId=$(echo "$RES" | jq '.requestId')

if [[ $requestId != "null" ]]; then
  echo "SSO URL: $SSO"
else
  echo "*"
fi

#Get the allowed_sudo_commands from the response
allowed_commands=$(echo "$RES" | jq -r '.dit.permissions[1].allowed_sudo_commands')
echo "Allowed Commands: $allowed_commands"

#Convert the allowed_commands to full path like /bin/ls,/bin/cat
IFS=',' read -r -a array <<< "$allowed_commands"
for element in "${array[@]}"
do
  echo "$element"
  full_path=$(which $element)
  echo "Full Path: $full_path"
done

#Update the allowed_commands with full path in sudoers file for the user
echo "$user ALL=(ALL) $full_path" >> /etc/sudoers
echo "User $user has been added to sudoers file with allowed commands"

#Check for syntax errors in sudoers file
visudo -c




content=$(sed '$ d' <<< "$requestId")
echo "$RES"
return 0
