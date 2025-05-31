# -*- coding: utf-8 -*-
"""
WSGI entry point for Render deployment
"""
from sistema_financeiro import PrimaArenaFinanceSystem

# Criar a instância global para o Gunicorn usar
system = PrimaArenaFinanceSystem()
app = system.app

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 8050))
    app.run(host='0.0.0.0', port=port, debug=False)
