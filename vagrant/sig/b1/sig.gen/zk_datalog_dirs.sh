#!/bin/bash

if [ ! -e /run/shm/host-zk ]; then
  echo 'Creating /run/shm/host-zk & restarting zookeeper'
  sudo mkdir -p /run/shm/host-zk
  sudo chown -R zookeeper: /run/shm/host-zk
  sudo service zookeeper restart
fi
