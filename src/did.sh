#!/bin/bash
 
echo "hello , Starting the Assertion"
string=$(groups $USER)
prefix="$USER : "
groupsStr=${string#"$prefix"}
echo "hiiii" ${PAM_USER}
 
hoststr=$(hostname -f)
prefixhost="Static hostname: "
hostname=${hoststr#"$prefixhost"}
 
input=$(tail -100 /var/log/auth.log | grep -oP '(?<=Postponed publickey for )\w+' | tail -1)
 
value=$(id -Gn $1)
 
user=$1
 
# Get the user ID of the specified username
userId=$(id -u $user)
echo "User ID: $userId"
 
# Determine credential type based on user ID range
if [[ $userId -ge 1 && $userId -le 999 ]]; then
  credentialType="SERVICEACCOUNT"
else
  credentialType="EPM"
fi
echo "Credential Type: $credentialType"
 
uuid=$(uuidgen)
echo $uuid
 
generate_post_data()
{
  cat <<EOF
{
  "username": "$(echo ${user})",
  "credentialType": "$credentialType",
  "hostname": "$(echo ${hoststr})",
  "groupName": "$(echo ${value})",
  "orgId": 84,
  "tenantId": 7,
  "requestId": "$(echo $uuid)",
  "userId": "$(echo $userId)"
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
 
content=$(sed '$ d' <<< "$requestId")
 
return 0
