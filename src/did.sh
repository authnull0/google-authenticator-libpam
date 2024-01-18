#!/bin/bash

echo "hello , Starting the Assertion"
string=`groups $USER`
prefix="$USER : "
groupsStr=${string#"$prefix"}
echo "hiiii" ${PAM_USER}
#echo "Env Vars:"
#env

hoststr=`hostname -f`
prefixhost="Static hostname: "
hostname=${hoststr#"$prefixhost"}
#echo $hostname

input=`tail -100 /var/log/auth.log | grep -oP '(?<=Postponed publickey for )\w+' | tail -1`
#echo "imput ${input}"
value=`id -Gn $1`


#user=`$1`
user=$1

#file="./conf.properties"

#while IFS='=' read -r key value
#do
#    key=$(echo $key | tr '.' '_')
#    eval ${key}=\${value}
#done < "$file"

#echo "User Id (ssh.pam.user) =         " ${ssh_pam_user}
#echo "user password (ssh.pam.groups) = " ${ssh_pam_groups}
uuid=$(uuidgen)
echo $uuid

generate_post_data()
{
  cat <<EOF
{
  "username": "`echo ${user}`" ,
  "credentialType": "EPM",
  "hostname": "`echo $hoststr`",
  "groupName": "`echo ${value}`",
  "orgId": 84,
  "tenantId": 7,
  "requestId": "`echo $uuid`"
}
EOF
}

echo $(generate_post_data)


echo "Script executed from: ${PWD}"
echo "First agr is $1"



RES=$(curl -H "Accept: application/json" -H "Content-Type:application/json" --connect-timeout 50 -m 50 -X POST --data "$(generate_post_data)"  "https://v1.api.authnull.com/authnull0/api/v1/authn/v3/do-authenticationV4")
SSO=$(echo "$RES" | jq -r '.ssoUrl')
echo "$SSO"

if [[ $(echo "$RES" | jq '.requestId') != "null" ]]; then
        echo "requestId Present in the response"
else
        echo "requestId not present in the response"
fi
#content=$(sed '$ d' <<< "$response")

#echo "$content"
return 0
