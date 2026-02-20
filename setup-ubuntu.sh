#!/bin/bash

# VPSphere Ubuntu Hyper-V Server Automated Setup Script
# This script installs all required dependencies to run the VPSphere Deployment Engine and Frontend.
# Run this file as root or with sudo: `sudo bash setup-ubuntu.sh`

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}Starting VPSphere Server Setup...${NC}"

# 1. Update Packages
echo -e "${YELLOW}Updating package lists...${NC}"
apt-get update -y
apt-get upgrade -y

# 2. Install Essentials
echo -e "${YELLOW}Installing essentials (Git, curl, build-essential)...${NC}"
apt-get install -y git curl build-essential openssh-server apt-transport-https ca-certificates software-properties-common

# 3. Install Node.js (v20 LTS)
echo -e "${YELLOW}Installing Node.js...${NC}"
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y nodejs
echo -e "Node version: $(node -v)"
echo -e "NPM version: $(npm -v)"

# 4. Install PM2 (Process Manager to keep apps running)
echo -e "${YELLOW}Installing PM2...${NC}"
npm install -g pm2

# 5. Install Docker & Docker Compose
echo -e "${YELLOW}Installing Docker...${NC}"
# Remove old versions if they exist
apt-get remove -y docker docker-engine docker.io containerd runc || true
# Install Docker and its CLI
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh
# Ensure Docker starts on boot
systemctl enable docker
systemctl start docker
# Add current user to docker group (assumes running via sudo)
usermod -aG docker $SUDO_USER || usermod -aG docker $(whoami)
echo -e "Docker version: $(docker --version)"

# 6. Install Redis Server (Required for BullMQ deployment engine)
echo -e "${YELLOW}Installing Redis...${NC}"
apt-get install -y redis-server
# Configure Redis to start on boot
systemctl enable redis-server
systemctl start redis-server

# 7. Install PostgreSQL (Required for Database)
echo -e "${YELLOW}Installing PostgreSQL...${NC}"
apt-get install -y postgresql postgresql-contrib
systemctl enable postgresql
systemctl start postgresql

echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}SUCCESS! Your Ubuntu Server is Ready.${NC}"
echo -e "${GREEN}=========================================${NC}"
echo -e "\n${YELLOW}Next Steps:${NC}"
echo -e "1. Please LOG OUT AND LOG BACK IN (or reboot) for Docker permissions to apply."
echo -e "2. Clone your backend: git clone https://github.com/daddyc00l69/deployment-engine-1.git"
echo -e "3. Clone your frontend: git clone https://github.com/daddyc00l69/vpsphere-2.git"
echo -e "4. Run 'npm install' in both folders."
echo -e "5. Create your .env files (Supabase JWT Secret, local DB/Redis URLs)."
echo -e "6. Use PM2 to start them: 'pm2 start server.js' and 'pm2 start npm --name frontend -- run start'"
