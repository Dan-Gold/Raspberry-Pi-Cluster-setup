#!/bin/bash

# Update current pi
sudo apt-get update -y
sudo apt-get upgrade -y

# Change the hostname to "rpi0"
sudo hostnamectl set-hostname rpi0

# Print the new hostname
echo "Hostname has been changed to: $(hostname)"

sudo reboot