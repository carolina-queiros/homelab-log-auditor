#!/usr/bin/env bash
# Simulates failed SSH logins and sudo activity on node-01

echo "[*] Generating test authentication events on node-01..."

ATTACKERS=("192.168.1.104" "10.0.0.45" "172.16.5.99")
USERS=("root" "admin" "test" "oracle" "deploy")

for i in {1..8}; do
    SRC_IP=${ATTACKERS[$RANDOM % ${#ATTACKERS[@]}]}
    USER=${USERS[$RANDOM % ${#USERS[@]}]}
    
    docker exec client_node_01 bash -c "echo \"\$(date '+%b %d %H:%M:%S') client_node_01 sshd[\$((RANDOM % 9000 + 1000))]: Failed password for invalid user $USER from $SRC_IP port 44322 ssh2\" >> /var/log/auth.log"
    sleep 0.5
done

docker exec client_node_01 bash -c "echo \"\$(date '+%b %d %H:%M:%S') client_node_01 sshd[12434]: Accepted publickey for student from 192.168.1.200 port 51234 ssh2\" >> /var/log/auth.log"
docker exec client_node_01 bash -c "echo \"\$(date '+%b %d %H:%M:%S') client_node_01 sudo: student : TTY=pts/0 ; PWD=/home/student ; USER=root ; COMMAND=/usr/bin/apt-get update\" >> /var/log/auth.log"

echo "[✓] Events written to /var/log/auth.log"
