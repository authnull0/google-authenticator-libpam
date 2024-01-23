#!/bin/bash

echo "Calling for Stage 2"

input=`tail -100 /var/log/auth.log | grep -oP '(?<=Postponed publickey for )\w+' | tail -1`
#echo "imput ${input}"

#user=`$1`
uUID=$1

#file="./conf.properties"

#while IFS='=' read -r key value
#do
#    key=$(echo $key | tr '.' '_')
#    eval ${key}=\${value}
#done < "$file"

#echo "User Id (ssh.pam.user) =         " ${ssh_pam_user}
#echo "user password (ssh.pam.groups) = " ${ssh_pam_groups}
generate_s2_post_data()
{
  cat <<EOF
{
  "requestId": "`echo $uUID`"
}
EOF
}

RES=$(curl -H "Accept: application/json" -H "Content-Type:application/json" --connect-timeout 120 -m 120 -X POST --data "$(generate_s2_post_data)"  "https://v1.api.authnull.com/authnull0/api/v1/authn/v3/do-authenticationV4Step2")
echo "$RES"

#echo "$content"
return 0
