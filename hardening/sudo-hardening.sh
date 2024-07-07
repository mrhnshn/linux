#!/bin/bash
if [[ $(dpkg --get-selections | grep -o sudo) ]]
then
  mkdir /etc/sudoers.d &>/dev/null
  chmod --quiet 700 /etc/sudoers.d
  chown --quiet root: /etc/sudoers.d
  echo "Defaults use_pty" > /etc/sudoers.d/configuration
  chmod --quiet 440 /etc/sudoers.d/configuration
  chown --quiet root: /etc/sudoers.d/configuration
fi
