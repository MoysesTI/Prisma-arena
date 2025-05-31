#!/usr/bin/env bash
# Script de build para o Render

echo "Criando diretórios necessários..."
mkdir -p uploads exports logs backups static/css static/js static/images templates

echo "Gerando pasta templates temporária se não existir..."
if [ ! -d "templates" ]; then
  mkdir -p templates
fi

echo "Build concluído com sucesso!"