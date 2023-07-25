#!/bin/bash

# Update current pi
sudo apt-get update -y
sudo apt-get upgrade -y

# Install tools
sudo apt-get install nmap -y
sudo apt-get install sshpass -y
sudo apt-get install vim -y
sudo apt autoremove -y

# Change the hostname to "rpi0"
sudo hostnamectl set-hostname rpi0

# Print the new hostname
echo "Hostname has been changed to: $(hostname)"

echo "This pi will reboot, next run 'node-ssh-setup.sh' which will configure all of the other raspberry pi nodes"
sudo reboot
