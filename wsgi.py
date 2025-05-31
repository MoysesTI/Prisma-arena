# -*- coding: utf-8 -*-
"""
WSGI entry point for Render deployment
"""
import os
from sistema_financeiro import PrimaArenaFinanceSystem

# Criar a instância da aplicação
system = PrimaArenaFinanceSystem()
app = system.app

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8050))
    app.run(host='0.0.0.0', port=port, debug=False)
