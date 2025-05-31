# -*- coding: utf-8 -*-
"""
WSGI entry point para o Render com codificação corrigida
"""
from flask_app import app

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 8050))
    app.run(host='0.0.0.0', port=port, debug=False)
