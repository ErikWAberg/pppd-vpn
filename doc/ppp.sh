#!/bin/sh
#Searches for a ppp Apple-service and prints it's state/configuration.


PATH=/usr/bin:/bin:/usr/sbin:/sbin

if2service() {
  local i
  for i in $(echo "list State:/Network/Service/[^/]+/PPP" | scutil | cut -d/ -f4); do
    if [[ "$(echo show State:/Network/Service/$i/PPP | scutil | grep InterfaceName | cut -d' ' -f5)" == ppp* ]]; then echo $i; return; fi
  done
}

SERVICE=$(if2service)
echo "PPP Service: $SERVICE"

echo "PPP State:"
echo show State:/Network/Service/$SERVICE/PPP | scutil
echo "IPv4 State:"
echo show State:/Network/Service/$SERVICE/IPv4 | scutil
echo "DNS State:"
echo show State:/Network/Service/$SERVICE/DNS | scutil
echo "Proxy State:"
scutil --proxy



