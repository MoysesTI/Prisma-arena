# -*- coding: utf-8 -*-
"""
Configurações para corrigir problemas de codificação de caracteres
"""
from sistema_financeiro import PrimaArenaFinanceSystem
import flask

# Criar instância do sistema
system = PrimaArenaFinanceSystem()
app = system.app

# Configurar codificação UTF-8 explicitamente
@app.after_request
def add_charset_header(response):
    if response.mimetype.startswith('text/'):
        response.headers['Content-Type'] = f'{response.mimetype}; charset=utf-8'
    return response
