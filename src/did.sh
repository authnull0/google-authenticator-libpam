#!/bin/bash

echo "hello , Starting the Assertion"
string=`groups $USER`
prefix="$USER : "
groupsStr=${string#"$prefix"}
#echo $groupsStr

hoststr=`hostname -f`
prefixhost="Static hostname: "
hostname=${hoststr#"$prefixhost"}
#echo $hostname

user=`id -u -n`
generate_post_data()
{
  cat <<EOF
{
  "username": "`echo $user`" ,
  "responseType": "ssh",
  "endpoint": "`echo $hoststr`",
  "group": "`echo $groupsStr`"
}
EOF
}

echo $(generate_post_data)


curl -H "Accept: application/json" \
-H "Content-Type:application/json" \
--connect-timeout 60 \
-m 60 \
-X POST --data "$(generate_post_data)" "https://api.did.kloudlearn.com/authnull0/api/v1/authn/do-authentication"

#content=$(sed '$ d' <<< "$response")

#echo "$content"
