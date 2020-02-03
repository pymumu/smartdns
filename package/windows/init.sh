#!/bin/bash

source /etc/os-release
case $ID in
debian|ubuntu)
    echo default wsl distro is debian or ubuntu.
    echo
    echo using default distro.
    echo
    exit 0
    ;;
*)
    echo default wsl distro is not debian or ubuntu.
    echo
    echo try to use ubuntu now.
    echo
    exit 1
    ;;
esac