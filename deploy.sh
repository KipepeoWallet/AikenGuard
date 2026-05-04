#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
# AikenGuard - Script de déploiement DEV → PROD
# ═══════════════════════════════════════════════════════════════════
# Copie tous les fichiers de ~/AikenGuard/public/ vers /var/www/aikenguard/
# Crée un backup horodaté avant chaque déploiement
# ═══════════════════════════════════════════════════════════════════

set -e  # Arrêt immédiat en cas d'erreur

# Configuration
SOURCE_DIR="$HOME/AikenGuard/public"
PROD_DIR="/var/www/aikenguard"
BACKUP_DIR="/var/backups/aikenguard"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Couleurs pour la lisibilité
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'  # No Color

echo ""
echo "🦋 AikenGuard - Déploiement DEV → PROD"
echo "════════════════════════════════════════"

# 1. Vérifications préalables
if [ ! -d "$SOURCE_DIR" ]; then
    echo -e "${RED}❌ Erreur: $SOURCE_DIR n'existe pas${NC}"
    exit 1
fi

NB_FILES=$(find "$SOURCE_DIR" -type f | wc -l)
if [ "$NB_FILES" -eq 0 ]; then
    echo -e "${RED}❌ Erreur: $SOURCE_DIR est vide${NC}"
    exit 1
fi

echo -e "Source : ${GREEN}$SOURCE_DIR${NC} ($NB_FILES fichiers)"
echo -e "Cible  : ${GREEN}$PROD_DIR${NC}"
echo ""

# 2. Backup de la version actuelle en prod
echo "📦 Étape 1/4 : Backup de la prod actuelle..."
sudo mkdir -p "$BACKUP_DIR"
if [ -d "$PROD_DIR" ] && [ "$(ls -A $PROD_DIR 2>/dev/null)" ]; then
    sudo cp -r "$PROD_DIR" "$BACKUP_DIR/backup_$TIMESTAMP"
    echo -e "   ${GREEN}✓${NC} Backup créé : $BACKUP_DIR/backup_$TIMESTAMP"
else
    echo -e "   ${YELLOW}⚠${NC}  Pas de prod existante à sauvegarder"
fi

# 3. Copie des fichiers
echo ""
echo "📤 Étape 2/4 : Copie des fichiers..."
sudo mkdir -p "$PROD_DIR"
sudo cp -r "$SOURCE_DIR"/* "$PROD_DIR"/
echo -e "   ${GREEN}✓${NC} $NB_FILES fichiers copiés"

# 4. Permissions Nginx
echo ""
echo "🔐 Étape 3/4 : Ajustement des permissions..."
sudo chown -R www-data:www-data "$PROD_DIR"
sudo chmod -R 644 "$PROD_DIR"/*
sudo find "$PROD_DIR" -type d -exec chmod 755 {} \;
echo -e "   ${GREEN}✓${NC} Permissions ajustées (www-data, 644/755)"

# 5. Test HTTP
echo ""
echo "🧪 Étape 4/4 : Test du site..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" https://aikenguard.io/)
if [ "$HTTP_CODE" = "200" ]; then
    echo -e "   ${GREEN}✓${NC} Site répond : HTTP $HTTP_CODE"
else
    echo -e "   ${RED}✗${NC} Site ne répond pas correctement : HTTP $HTTP_CODE"
fi

# 6. Résumé
echo ""
echo "════════════════════════════════════════"
echo -e "${GREEN}✅ Déploiement terminé !${NC}"
echo ""
echo "📂 Fichiers déployés :"
ls -la "$PROD_DIR" | grep -v '^total' | grep -v '^d' | awk '{print "   " $NF " (" $5 " bytes)"}'
echo ""
echo "💾 Backups disponibles dans $BACKUP_DIR :"
ls -lt "$BACKUP_DIR" 2>/dev/null | grep '^d' | head -5 | awk '{print "   " $NF}'
echo ""
