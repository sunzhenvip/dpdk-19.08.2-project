#!/bin/bash

ip netns add vlan100
ip netns add vlan101
ip netns add vlan102

ip netns add vlan200
ip netns add vlan201
ip netns add vlan202

ip link add vlan100dev type veth peer name vlan100_eth
ip link add vlan101dev type veth peer name vlan101_eth
ip link add vlan102dev type veth peer name vlan102_eth

ip link add vlan200dev type veth peer name vlan200_eth
ip link add vlan201dev type veth peer name vlan201_eth
ip link add vlan202dev type veth peer name vlan202_eth


ip link set vlan100dev netns vlan100
ip link set vlan101dev netns vlan101
ip link set vlan102dev netns vlan102

ip link set vlan200dev netns vlan200
ip link set vlan201dev netns vlan201
ip link set vlan202dev netns vlan202


ip netns exec vlan100 ip address add 192.168.6.100/24 dev vlan100dev
ip netns exec vlan100 ip link set vlan100dev up
ip link set vlan100_eth up


ip netns exec vlan101 ip address add 192.168.6.101/24 dev vlan101dev
ip netns exec vlan101 ip link set vlan101dev up
ip link set vlan101_eth up

ip netns exec vlan102 ip address add 192.168.6.102/24 dev vlan102dev
ip netns exec vlan102 ip link set vlan102dev up
ip link set vlan102_eth up

ip netns exec vlan200 ip address add 192.168.6.200/24 dev vlan200dev
ip netns exec vlan200 ip link set vlan200dev up
ip link set vlan200_eth up

ip netns exec vlan201 ip address add 192.168.6.201/24 dev vlan201dev
ip netns exec vlan201 ip link set vlan201dev up
ip link set vlan201_eth up

ip netns exec vlan202 ip address add 192.168.6.202/24 dev vlan202dev
ip netns exec vlan202 ip link set vlan202dev up
ip link set vlan202_eth up



