#!/bin/bash
echo "PCR-QUIC GitHub Setup"
echo ""
echo "1. First, create the repository on GitHub:"
echo "   - Go to: https://github.com/new"
echo "   - Name: pcr-quic"
echo "   - Description: PCR-QUIC: Double Ratchet Protocol for QUIC with Forward Secrecy and Post-Compromise Security"
echo "   - Make it PUBLIC"
echo "   - DO NOT initialize with README"
echo ""
echo "2. Then, enter your GitHub username:"
read -p "GitHub username: " username
echo ""
echo "3. Choose authentication method:"
echo "   1) HTTPS (recommended, will prompt for password/token)"
echo "   2) SSH (requires SSH key setup)"
read -p "Choice (1 or 2): " auth_choice

if [ "$auth_choice" == "1" ]; then
    remote_url="https://github.com/$username/pcr-quic.git"
else
    remote_url="git@github.com:$username/pcr-quic.git"
fi

echo ""
echo "Setting up remote and pushing..."
git remote add origin "$remote_url"
git branch -M main
git push -u origin main

echo ""
echo "✅ Done! Your repository is at: https://github.com/$username/pcr-quic"
