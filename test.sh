#!/bin/bash

echo "=== Test du firewall eBPF ==="

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}1. Démarrage d'un serveur web de test sur le port 8080...${NC}"
python3 -m http.server 8080 > /dev/null 2>&1 &
SERVER_PID=$!
sleep 2

echo -e "${YELLOW}2. Test de connexion sur port autorisé (80)...${NC}"
# Démarrer un serveur sur le port 80
sudo python3 -m http.server 80 > /dev/null 2>&1 &
SERVER80_PID=$!
sleep 2

# Tester la connexion
if curl -s --connect-timeout 5 http://localhost:80 > /dev/null; then
    echo -e "${GREEN}✓ Port 80 accessible (devrait être autorisé)${NC}"
else
    echo -e "${RED}✗ Port 80 bloqué${NC}"
fi

echo -e "${YELLOW}3. Test de connexion sur port non autorisé (8080)...${NC}"
if curl -s --connect-timeout 5 http://localhost:8080 > /dev/null; then
    echo -e "${RED}✗ Port 8080 accessible (devrait être bloqué)${NC}"
else
    echo -e "${GREEN}✓ Port 8080 bloqué correctement${NC}"
fi

echo -e "${YELLOW}4. Test ICMP (ping)...${NC}"
if ping -c 1 -W 2 127.0.0.1 > /dev/null 2>&1; then
    echo -e "${GREEN}✓ ICMP (ping) fonctionne${NC}"
else
    echo -e "${RED}✗ ICMP (ping) bloqué${NC}"
fi

echo -e "${YELLOW}5. Monitoring des paquets avec tcpdump...${NC}"
echo "Lancez dans un autre terminal :"
echo "sudo tcpdump -i lo -n 'port 80 or port 8080'"

# Nettoyage
kill $SERVER_PID $SERVER80_PID 2>/dev/null
echo -e "${YELLOW}Test terminé.${NC}"