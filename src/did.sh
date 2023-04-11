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

generate_post_data()
{
  cat <<EOF
{
  "username": "`echo ${user}`" ,
  "responseType": "ssh",
  "endpoint": "`echo $hoststr`",
  "group": "`echo ${value}`"
}
EOF
}

echo $(generate_post_data)


echo "Script executed from: ${PWD}"
echo "First agr is $1"



curl -H "Accept: application/json" \
-H "Content-Type:application/json" \
--connect-timeout 50 \
-m 50 \
-X POST --data "$(generate_post_data)" "https://api.did.kloudlearn.com/authnull0/api/v1/authn/do-authentication"

#content=$(sed '$ d' <<< "$response")

#echo "$content"
return 0
