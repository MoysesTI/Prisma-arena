# -*- coding: utf-8 -*-
"""
Sistema Financeiro Prima Arena Finance - Versão Corrigida COMPLETA
Correção do erro de URL + Unicode + Manutenção de TODAS as funcionalidades
"""
import os
import sqlite3
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import calendar
import logging
import base64
import json
import hashlib
from pathlib import Path
import uuid
import io

# Flask
from flask import Flask, render_template, request, redirect, url_for, flash, session, g, jsonify, send_file
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

# Dash e Plotly
import dash
from dash import dcc, html, dash_table, callback_context
import dash_bootstrap_components as dbc
from dash.dependencies import Input, Output, State, ALL
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# Configurar logging sem emojis para Windows
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('finance_system.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# =====================================================
# CONFIGURAÇÕES E CONSTANTES
# =====================================================

BASE_DIR = Path(__file__).parent
UPLOAD_FOLDER = BASE_DIR / 'uploads'
DB_PATH = BASE_DIR / 'finance_system.db'
STATIC_FOLDER = BASE_DIR / 'static'
EXPORT_FOLDER = BASE_DIR / 'exports'
TEMPLATES_FOLDER = BASE_DIR / 'templates'

# Criar pastas necessárias
for folder in [UPLOAD_FOLDER, STATIC_FOLDER, EXPORT_FOLDER, TEMPLATES_FOLDER]:
    folder.mkdir(exist_ok=True)

# Configurações do sistema
CONFIG = {
    'MAX_FILE_SIZE': 50 * 1024 * 1024,  # 50MB
    'ALLOWED_EXTENSIONS': {'xlsx', 'xls', 'csv', 'txt', 'json'},
    'DATE_FORMATS': ['%d/%m/%Y', '%Y-%m-%d', '%d-%m-%Y', '%d/%m/%y', '%Y/%m/%d'],
    'CURRENCY_SYMBOL': 'R$',
    'APP_NAME': 'Prima Arena Finance',
    'VERSION': '2.1.0',
    'ADMIN_USERS': {
        'PrimaArenaFinance': 'Prisma@2025ArenaL1MoysesK',
    }
}

# Paletas de cores profissionais aprimoradas
COLOR_PALETTES = {
    'prima_arena': ['#1f4e79', '#2e8b57', '#dc143c', '#ff8c00', '#4b0082', '#8b4513', '#00ced1', '#ff1493'],
    'financeiro': ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b', '#e377c2', '#7f7f7f'],
    'moderno': ['#667eea', '#764ba2', '#f093fb', '#f5576c', '#4facfe', '#00f2fe', '#43e97b', '#38f9d7'],
    'analise': ['#2E86AB', '#A23B72', '#F18F01', '#C73E1D', '#592E83', '#F79824', '#A4036F', '#048A81']
}

# =====================================================
# CLASSE DE GERENCIAMENTO DO BANCO DE DADOS
# =====================================================

class DatabaseManager:
    def __init__(self, db_path):
        self.db_path = db_path
        self.init_database()

    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_database(self):
        try:
            with self.get_connection() as conn:
                # Tabela de usuários
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        email TEXT,
                        full_name TEXT,
                        role TEXT DEFAULT 'user',
                        is_active BOOLEAN DEFAULT 1,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_login TIMESTAMP,
                        login_count INTEGER DEFAULT 0
                    )
                ''')

                # Tabela de arquivos
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS uploaded_files (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER,
                        filename TEXT NOT NULL,
                        original_filename TEXT NOT NULL,
                        file_path TEXT NOT NULL,
                        file_size INTEGER,
                        file_type TEXT,
                        upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        processed BOOLEAN DEFAULT 0,
                        records_count INTEGER DEFAULT 0,
                        total_value REAL DEFAULT 0,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )
                ''')

                # Tabela de análises salvas
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS saved_analyses (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER,
                        file_id INTEGER,
                        analysis_name TEXT NOT NULL,
                        description TEXT,
                        filters_json TEXT,
                        chart_config_json TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        is_favorite BOOLEAN DEFAULT 0,
                        view_count INTEGER DEFAULT 0,
                        FOREIGN KEY (user_id) REFERENCES users (id),
                        FOREIGN KEY (file_id) REFERENCES uploaded_files (id)
                    )
                ''')

                # Tabela de logs
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS system_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER,
                        action TEXT NOT NULL,
                        details TEXT,
                        ip_address TEXT,
                        user_agent TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )
                ''')

                # Inserir usuários admin
                for username, password in CONFIG['ADMIN_USERS'].items():
                    password_hash = generate_password_hash(password)
                    conn.execute('''
                        INSERT OR IGNORE INTO users (username, password_hash, role, full_name, email)
                        VALUES (?, ?, 'admin', ?, ?)
                    ''', (username, password_hash, f'Administrador {username}', f'{username.lower()}@primaarena.com'))

                conn.commit()
                logger.info("Banco de dados inicializado com sucesso")

        except Exception as e:
            logger.error(f"Erro ao inicializar banco: {e}")
            raise

    def authenticate_user(self, username, password):
        try:
            with self.get_connection() as conn:
                user = conn.execute('''
                    SELECT id, username, password_hash, role, full_name, is_active
                    FROM users
                    WHERE username = ? AND is_active = 1
                ''', (username,)).fetchone()

                if user and check_password_hash(user['password_hash'], password):
                    conn.execute('''
                        UPDATE users
                        SET last_login = CURRENT_TIMESTAMP, login_count = login_count + 1
                        WHERE id = ?
                    ''', (user['id'],))
                    conn.commit()
                    return dict(user)
                return None
        except Exception as e:
            logger.error(f"Erro na autenticação: {e}")
            return None

    def log_user_action(self, user_id, action, details=None, ip_address=None, user_agent=None):
        try:
            with self.get_connection() as conn:
                conn.execute('''
                    INSERT INTO system_logs (user_id, action, details, ip_address, user_agent)
                    VALUES (?, ?, ?, ?, ?)
                ''', (user_id, action, details, ip_address, user_agent))
                conn.commit()
        except Exception as e:
            logger.error(f"Erro ao registrar log: {e}")

    def save_uploaded_file_info(self, user_id, filename, original_filename, file_path, file_size, file_type):
        try:
            with self.get_connection() as conn:
                cursor = conn.execute('''
                    INSERT INTO uploaded_files
                    (user_id, filename, original_filename, file_path, file_size, file_type)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (user_id, filename, original_filename, file_path, file_size, file_type))
                conn.commit()
                return cursor.lastrowid
        except Exception as e:
            logger.error(f"Erro ao salvar info do arquivo: {e}")
            return None

# =====================================================
# CLASSE PRINCIPAL DO SISTEMA COMPLETO
# =====================================================

class PrimaArenaFinanceSystem:
    def __init__(self):
        self.app = Flask(__name__)
        self.app.secret_key = 'prima-arena-finance-secret-key-2025'
        self.db = DatabaseManager(DB_PATH)
        self.setup_flask_config()
        self.setup_routes()
        self.dash_app = self.create_dash_app()

    def setup_flask_config(self):
        self.app.config.update({
            'UPLOAD_FOLDER': str(UPLOAD_FOLDER),
            'MAX_CONTENT_LENGTH': CONFIG['MAX_FILE_SIZE'],
            'TEMPLATES_AUTO_RELOAD': True,
            'JSON_AS_ASCII': False
        })
        
        # Adicionar contexto global para templates
        @self.app.context_processor
        def inject_globals():
            return {
                'current_year': datetime.now().year,
                'app_name': CONFIG['APP_NAME'],
                'app_version': CONFIG['VERSION']
            }

    def setup_routes(self):
        @self.app.before_request
        def load_logged_in_user():
            user_id = session.get('user_id')
            if user_id is None:
                g.user = None
            else:
                with self.db.get_connection() as conn:
                    g.user = conn.execute(
                        'SELECT * FROM users WHERE id = ?', (user_id,)
                    ).fetchone()

        @self.app.route('/')
        def index():
            if g.user is None:
                return redirect(url_for('login'))
            return redirect(url_for('dashboard'))

        @self.app.route('/login', methods=['GET', 'POST'])
        def login():
            if request.method == 'POST':
                username = request.form.get('username')
                password = request.form.get('password')

                user = self.db.authenticate_user(username, password)

                if user:
                    session.clear()
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['role'] = user['role']
                    session['full_name'] = user['full_name']

                    self.db.log_user_action(
                        user['id'],
                        'LOGIN',
                        f"Login realizado com sucesso",
                        request.environ.get('REMOTE_ADDR'),
                        request.environ.get('HTTP_USER_AGENT')
                    )

                    flash(f'Bem-vindo, {user["full_name"]}!', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Usuário ou senha inválidos!', 'danger')

            return render_template('login.html')

        @self.app.route('/logout')
        def logout():
            if g.user:
                self.db.log_user_action(g.user['id'], 'LOGOUT', 'Logout realizado')
            session.clear()
            flash('Logout realizado com sucesso!', 'info')
            return redirect(url_for('login'))

        @self.app.route('/dashboard')
        def dashboard():
            if g.user is None:
                return redirect(url_for('login'))

            with self.db.get_connection() as conn:
                stats_row = conn.execute('''
                    SELECT
                        COUNT(*) as total_files,
                        COALESCE(SUM(records_count), 0) as total_records,
                        COALESCE(SUM(total_value), 0) as total_value
                    FROM uploaded_files
                    WHERE user_id = ?
                ''', (g.user['id'],)).fetchone()

                recent_files = conn.execute('''
                    SELECT * FROM uploaded_files
                    WHERE user_id = ?
                    ORDER BY upload_date DESC
                    LIMIT 10
                ''', (g.user['id'],)).fetchall()

            return render_template('dashboard.html', 
                                 stats=dict(stats_row) if stats_row else {}, 
                                 files=recent_files,
                                 CURRENCY_SYMBOL=CONFIG['CURRENCY_SYMBOL'])

        @self.app.route('/upload', methods=['POST'])
        def upload_file():
            if g.user is None:
                return redirect(url_for('login'))

            if 'file' not in request.files:
                flash('Nenhum arquivo selecionado', 'danger')
                return redirect(url_for('dashboard'))

            file = request.files['file']
            if file.filename == '':
                flash('Nenhum arquivo selecionado', 'danger')
                return redirect(url_for('dashboard'))

            if file and self.allowed_file(file.filename):
                try:
                    original_filename = file.filename
                    filename = secure_filename(file.filename)
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    name, ext = os.path.splitext(filename)
                    unique_filename = f"{name}_{timestamp}_{uuid.uuid4().hex[:8]}{ext}"

                    file_path = UPLOAD_FOLDER / unique_filename
                    file.save(str(file_path))

                    file_id = self.db.save_uploaded_file_info(
                        g.user['id'],
                        unique_filename,
                        original_filename,
                        str(file_path),
                        file_path.stat().st_size,
                        ext
                    )

                    self.db.log_user_action(
                        g.user['id'],
                        'FILE_UPLOAD',
                        f"Upload do arquivo: {original_filename}"
                    )

                    flash(f'Arquivo {original_filename} enviado com sucesso!', 'success')
                    return redirect(url_for('analyze_file', file_id=file_id))

                except Exception as e:
                    logger.error(f"Erro no upload: {e}")
                    flash('Erro ao fazer upload do arquivo', 'danger')
            else:
                flash('Tipo de arquivo não permitido', 'danger')

            return redirect(url_for('dashboard'))

        @self.app.route('/analyze/<int:file_id>')
        def analyze_file(file_id):
            if g.user is None:
                return redirect(url_for('login'))

            with self.db.get_connection() as conn:
                file_info = conn.execute('''
                    SELECT * FROM uploaded_files
                    WHERE id = ? AND user_id = ?
                ''', (file_id, g.user['id'])).fetchone()

            if not file_info:
                flash('Arquivo não encontrado', 'danger')
                return redirect(url_for('dashboard'))

            session['current_file_id'] = file_id
            return redirect('/dash/')

        @self.app.route('/api/file-data/<int:file_id>')
        def get_file_data(file_id):
            if g.user is None:
                return jsonify({'error': 'Não autorizado'}), 401

            try:
                with self.db.get_connection() as conn:
                    file_info = conn.execute('''
                        SELECT * FROM uploaded_files
                        WHERE id = ? AND user_id = ?
                    ''', (file_id, g.user['id'])).fetchone()

                if not file_info:
                    return jsonify({'error': 'Arquivo não encontrado'}), 404

                df, stats_data = self.process_file(Path(file_info['file_path']))

                return jsonify({
                    'success': True,
                    'data': df.to_dict('records'),
                    'columns': df.columns.tolist(),
                    'stats': stats_data,
                    'file_info': dict(file_info)
                })

            except Exception as e:
                logger.error(f"Erro ao processar arquivo: {e}")
                return jsonify({'error': str(e)}), 500

        @self.app.route('/admin')
        def admin_panel():
            if g.user is None or g.user['role'] != 'admin':
                flash('Acesso negado', 'danger')
                return redirect(url_for('dashboard'))

            with self.db.get_connection() as conn:
                system_stats_row = conn.execute('''
                    SELECT
                        (SELECT COUNT(*) FROM users) as total_users,
                        (SELECT COUNT(*) FROM uploaded_files) as total_files,
                        (SELECT COUNT(*) FROM saved_analyses) as total_analyses,
                        (SELECT COUNT(*) FROM system_logs WHERE DATE(timestamp) = DATE('now')) as today_actions
                ''').fetchone()

                recent_logs = conn.execute('''
                    SELECT sl.*, u.username
                    FROM system_logs sl
                    LEFT JOIN users u ON sl.user_id = u.id
                    ORDER BY sl.timestamp DESC
                    LIMIT 20
                ''').fetchall()

            return render_template('admin.html', 
                                 stats=dict(system_stats_row) if system_stats_row else {}, 
                                 logs=recent_logs)

    def create_dash_app(self):
        dash_app = dash.Dash(
            __name__,
            server=self.app,
            url_base_pathname='/dash/',
            external_stylesheets=[
                dbc.themes.BOOTSTRAP,
                'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css'
            ],
            suppress_callback_exceptions=True,
            title=CONFIG['APP_NAME']
        )

        dash_app.layout = self.create_enhanced_dash_layout()
        self.setup_enhanced_callbacks(dash_app)
        return dash_app

    def create_enhanced_dash_layout(self):
        return dbc.Container([
            # Header Aprimorado
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            dbc.Row([
                                dbc.Col([
                                    html.H1([
                                        html.I(className="fas fa-chart-line me-2 text-primary"),
                                        CONFIG['APP_NAME']
                                    ], className="mb-1"),
                                    html.P("Dashboard Financeiro - Análises Avançadas", className="text-muted mb-0")
                                ], md=8),
                                dbc.Col([
                                    dbc.ButtonGroup([
                                        dbc.Button([
                                            html.I(className="fas fa-sync me-1"),
                                            "Atualizar"
                                        ], id="btn-refresh", color="primary", size="sm"),
                                        dbc.Button([
                                            html.I(className="fas fa-download me-1"),
                                            "Exportar"
                                        ], id="btn-export", color="success", size="sm"),
                                        dbc.Button([
                                            html.I(className="fas fa-save me-1"),
                                            "Salvar"
                                        ], id="btn-save", color="info", size="sm")
                                    ], className="float-end")
                                ], md=4)
                            ])
                        ])
                    ], className="mb-4 shadow-sm border-0")
                ])
            ]),

            # Seção de Upload e Seleção
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader([
                            html.H5([
                                html.I(className="fas fa-file-upload me-2"),
                                "Dados para Análise"
                            ], className="mb-0 text-primary")
                        ]),
                        dbc.CardBody([
                            dbc.Row([
                                dbc.Col([
                                    html.Label("Selecionar Arquivo:", className="fw-bold mb-2"),
                                    dcc.Dropdown(
                                        id='file-selector',
                                        placeholder="Escolha um arquivo para análise...",
                                        className="mb-2"
                                    ),
                                ], md=8),
                                dbc.Col([
                                    html.Label("Status:", className="fw-bold mb-2"),
                                    html.Div(id="file-status", className="text-center")
                                ], md=4)
                            ])
                        ])
                    ])
                ], md=12, className="mb-4")
            ]),

            # Cards de Resumo Inteligentes
            dbc.Row(id="smart-summary-cards", className="mb-4"),

            # Painel de Filtros Avançado
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader([
                            dbc.Row([
                                dbc.Col([
                                    html.H5([
                                        html.I(className="fas fa-filter me-2"),
                                        "Filtros Inteligentes"
                                    ], className="mb-0 text-primary")
                                ], md=8),
                                dbc.Col([
                                    dbc.Button(
                                        [html.I(className="fas fa-chevron-down me-1"), "Expandir"],
                                        id="toggle-filters",
                                        color="outline-primary",
                                        size="sm",
                                        className="float-end"
                                    )
                                ], md=4)
                            ])
                        ]),
                        dbc.Collapse([
                            dbc.CardBody([
                                # Filtros Rápidos de Data Melhorados
                                dbc.Row([
                                    dbc.Col([
                                        html.Label("⚡ Filtros Rápidos de Período:", className="fw-bold mb-2 text-info"),
                                        dbc.ButtonGroup([
                                            dbc.Button("Hoje", id="btn-hoje", color="info", size="sm", outline=True),
                                            dbc.Button("Ontem", id="btn-ontem", color="info", size="sm", outline=True),
                                            dbc.Button("Esta Semana", id="btn-esta-semana", color="info", size="sm", outline=True),
                                            dbc.Button("Semana Passada", id="btn-semana-passada", color="info", size="sm", outline=True),
                                        ], className="w-100 mb-2"),
                                        dbc.ButtonGroup([
                                            dbc.Button("Últimos 7 Dias", id="btn-7dias", color="warning", size="sm", outline=True),
                                            dbc.Button("Últimos 15 Dias", id="btn-15dias", color="warning", size="sm", outline=True),
                                            dbc.Button("Últimos 30 Dias", id="btn-30dias", color="warning", size="sm", outline=True),
                                            dbc.Button("Últimos 90 Dias", id="btn-90dias", color="warning", size="sm", outline=True),
                                        ], className="w-100 mb-2"),
                                        dbc.ButtonGroup([
                                            dbc.Button("Este Mês", id="btn-este-mes", color="success", size="sm", outline=True),
                                            dbc.Button("Mês Passado", id="btn-mes-passado", color="success", size="sm", outline=True),
                                            dbc.Button("Este Ano", id="btn-este-ano", color="success", size="sm", outline=True),
                                            dbc.Button("Limpar Filtros", id="btn-clear-filters", color="secondary", size="sm")
                                        ], className="w-100 mb-3")
                                    ], md=12)
                                ]),

                                # Filtros por Dia da Semana
                                dbc.Row([
                                    dbc.Col([
                                        html.Label("📅 Filtros por Dia da Semana:", className="fw-bold mb-2 text-primary"),
                                        dbc.ButtonGroup([
                                            dbc.Button("Seg", id="btn-segunda", color="outline-primary", size="sm"),
                                            dbc.Button("Ter", id="btn-terca", color="outline-primary", size="sm"),
                                            dbc.Button("Qua", id="btn-quarta", color="outline-primary", size="sm"),
                                            dbc.Button("Qui", id="btn-quinta", color="outline-primary", size="sm"),
                                            dbc.Button("Sex", id="btn-sexta", color="outline-primary", size="sm"),
                                            dbc.Button("Sáb", id="btn-sabado", color="outline-primary", size="sm"),
                                            dbc.Button("Dom", id="btn-domingo", color="outline-primary", size="sm"),
                                        ], className="w-100 mb-3")
                                    ], md=12)
                                ]),

                                # Filtros Detalhados
                                dbc.Row([
                                    dbc.Col([
                                        html.Label("Período Personalizado:", className="fw-bold text-primary"),
                                        dcc.DatePickerRange(
                                            id='date-picker',
                                            display_format='DD/MM/YYYY',
                                            start_date_placeholder_text='Data Inicial',
                                            end_date_placeholder_text='Data Final',
                                            className="w-100 mb-2"
                                        )
                                    ], md=6),
                                    dbc.Col([
                                        html.Label("Faixa de Valores:", className="fw-bold text-success"),
                                        dcc.RangeSlider(
                                            id='value-range',
                                            tooltip={"placement": "bottom", "always_visible": True},
                                            className="mb-2"
                                        ),
                                        html.Div(id="value-range-display", className="text-center text-muted small")
                                    ], md=6)
                                ], className="mb-3"),

                                dbc.Row([
                                    dbc.Col([
                                        html.Label("Tipo de Banco:", className="fw-bold text-warning"),
                                        dcc.Dropdown(
                                            id='filter-banco',
                                            multi=True,
                                            placeholder="Selecione bancos...",
                                            className="mb-2"
                                        )
                                    ], md=4),
                                    dbc.Col([
                                        html.Label("Categoria:", className="fw-bold text-danger"),
                                        dcc.Dropdown(
                                            id='filter-categoria',
                                            multi=True,
                                            placeholder="Selecione categorias...",
                                            className="mb-2"
                                        )
                                    ], md=4),
                                    dbc.Col([
                                        html.Label("Forma de Recebimento:", className="fw-bold text-info"),
                                        dcc.Dropdown(
                                            id='filter-forma',
                                            multi=True,
                                            placeholder="Selecione formas...",
                                            className="mb-2"
                                        )
                                    ], md=4)
                                ]),

                                # Indicador de Filtros Ativos
                                dbc.Row([
                                    dbc.Col([
                                        html.Div(id="active-filters-display", className="mb-3")
                                    ], md=12)
                                ]),

                                dbc.Row([
                                    dbc.Col([
                                        dbc.Button([
                                            html.I(className="fas fa-filter me-2"),
                                            "Aplicar Filtros"
                                        ], id="apply-filters", color="primary", className="me-2"),
                                        dbc.Button([
                                            html.I(className="fas fa-redo me-2"),
                                            "Resetar Tudo"
                                        ], id="reset-all", color="secondary")
                                    ], className="text-center mt-3")
                                ])
                            ])
                        ], id="collapse-filters", is_open=False)
                    ])
                ], md=12, className="mb-4")
            ]),

            # Área Principal de Gráficos
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader([
                            dbc.Tabs([
                                dbc.Tab(label="Visão Geral", tab_id="tab-overview"),
                                dbc.Tab(label="Análise por Banco", tab_id="tab-banco"),
                                dbc.Tab(label="Análise por Categoria", tab_id="tab-categoria"),
                                dbc.Tab(label="Formas de Recebimento", tab_id="tab-forma"),
                                dbc.Tab(label="Tendências", tab_id="tab-trends"),
                                dbc.Tab(label="Distribuições", tab_id="tab-distributions")
                            ], id="main-tabs", active_tab="tab-overview")
                        ]),
                        dbc.CardBody([
                            html.Div(id="main-chart-content", className="min-height-500")
                        ])
                    ])
                ])
            ], className="mb-4"),

            # Tabela de Dados
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader([
                            dbc.Row([
                                dbc.Col([
                                    html.H5([
                                        html.I(className="fas fa-table me-2"),
                                        "Dados Detalhados"
                                    ], className="mb-0")
                                ], md=6),
                                dbc.Col([
                                    html.Div(id="table-info", className="text-end text-muted")
                                ], md=6)
                            ])
                        ]),
                        dbc.CardBody([
                            html.Div(id="data-table-container")
                        ])
                    ])
                ])
            ]),

            # Stores para dados
            dcc.Store(id='raw-data'),
            dcc.Store(id='filtered-data'),
            dcc.Store(id='filter-stats'),

            # Interval para atualizações
            dcc.Interval(id='interval-component', interval=30000, n_intervals=0)

        ], fluid=True, className="p-4 bg-light")

    def setup_enhanced_callbacks(self, dash_app):
        # Callback principal para carregar dados
        @dash_app.callback(
            [Output('file-selector', 'options'),
             Output('raw-data', 'data'),
             Output('file-status', 'children')],
            [Input('file-selector', 'value'),
             Input('interval-component', 'n_intervals')]
        )
        def load_data(selected_file_id, n_intervals):
            if not selected_file_id:
                return self.get_file_options(), None, self.create_status_badge("Nenhum arquivo selecionado", "secondary")

            try:
                with self.db.get_connection() as conn:
                    file_info = conn.execute('''
                        SELECT * FROM uploaded_files WHERE id = ?
                    ''', (selected_file_id,)).fetchone()

                if file_info:
                    df, stats_data = self.process_file(Path(file_info['file_path']))

                    return (
                        self.get_file_options(),
                        {
                            'data': df.to_dict('records'),
                            'columns': df.columns.tolist(),
                            'stats': stats_data,
                            'file_info': dict(file_info)
                        },
                        self.create_status_badge(f"✓ {len(df):,} registros carregados", "success")
                    )

            except Exception as e:
                logger.error(f"Erro ao carregar dados: {e}")
                return self.get_file_options(), None, self.create_status_badge("✗ Erro ao carregar", "danger")

            return self.get_file_options(), None, self.create_status_badge("Arquivo não encontrado", "warning")

        # Callback para atualizar opções de filtros
        @dash_app.callback(
            [Output('filter-banco', 'options'),
             Output('filter-categoria', 'options'),
             Output('filter-forma', 'options'),
             Output('value-range', 'min'),
             Output('value-range', 'max'),
             Output('value-range', 'value'),
             Output('date-picker', 'start_date'),
             Output('date-picker', 'end_date')],
            [Input('raw-data', 'data')]
        )
        def update_filter_options(data):
            if not data:
                return [], [], [], 0, 100, [0, 100], None, None

            df = pd.DataFrame(data['data'])

            # Opções para dropdowns
            banco_opts = self.get_dropdown_options(df, 'Tipo Banco')
            categoria_opts = self.get_dropdown_options(df, 'Categoria')
            forma_opts = self.get_dropdown_options(df, 'Forma de Recebimento')

            # Range de valores
            min_val, max_val = self.get_value_range(df)

            # Datas
            start_date, end_date = self.get_date_range(df)

            return (banco_opts, categoria_opts, forma_opts,
                    min_val, max_val, [min_val, max_val],
                    start_date, end_date)

        # Callback para aplicar filtros MELHORADO
        @dash_app.callback(
            [Output('filtered-data', 'data'),
             Output('filter-stats', 'data')],
            [Input('apply-filters', 'n_clicks'),
             Input('btn-hoje', 'n_clicks'),
             Input('btn-ontem', 'n_clicks'),
             Input('btn-esta-semana', 'n_clicks'),
             Input('btn-semana-passada', 'n_clicks'),
             Input('btn-7dias', 'n_clicks'),
             Input('btn-15dias', 'n_clicks'),
             Input('btn-30dias', 'n_clicks'),
             Input('btn-90dias', 'n_clicks'),
             Input('btn-este-mes', 'n_clicks'),
             Input('btn-mes-passado', 'n_clicks'),
             Input('btn-este-ano', 'n_clicks'),
             Input('btn-segunda', 'n_clicks'),
             Input('btn-terca', 'n_clicks'),
             Input('btn-quarta', 'n_clicks'),
             Input('btn-quinta', 'n_clicks'),
             Input('btn-sexta', 'n_clicks'),
             Input('btn-sabado', 'n_clicks'),
             Input('btn-domingo', 'n_clicks'),
             Input('btn-clear-filters', 'n_clicks'),
             Input('reset-all', 'n_clicks')],
            [State('raw-data', 'data'),
             State('filter-banco', 'value'),
             State('filter-categoria', 'value'),
             State('filter-forma', 'value'),
             State('value-range', 'value'),
             State('date-picker', 'start_date'),
             State('date-picker', 'end_date')]
        )
        def apply_enhanced_filters(apply_n, hoje_n, ontem_n, esta_semana_n, semana_passada_n,
                                 dias7_n, dias15_n, dias30_n, dias90_n, este_mes_n, mes_passado_n, 
                                 este_ano_n, segunda_n, terca_n, quarta_n, quinta_n, sexta_n, 
                                 sabado_n, domingo_n, clear_n, reset_n,
                                 data, banco_filter, categoria_filter, forma_filter,
                                 valor_filter, start_date, end_date):

            if not data:
                return None, {}

            ctx = callback_context
            df = pd.DataFrame(data['data'])

            if not ctx.triggered:
                filtered_df = df
            else:
                trigger_id = ctx.triggered[0]['prop_id'].split('.')[0]

                if trigger_id in ['btn-clear-filters', 'reset-all']:
                    filtered_df = df
                else:
                    filtered_df = self.apply_enhanced_smart_filters(
                        df, trigger_id, banco_filter, categoria_filter, forma_filter,
                        valor_filter, start_date, end_date
                    )

            # Calcular estatísticas dos dados filtrados
            filter_stats_data = self.calculate_filter_statistics(filtered_df, df)

            return {
                'data': filtered_df.to_dict('records'),
                'columns': filtered_df.columns.tolist(),
                'filtered': len(filtered_df) != len(df),
                'original_count': len(df),
                'filtered_count': len(filtered_df)
            }, filter_stats_data

        # Callback para cards de resumo inteligentes
        @dash_app.callback(
            Output('smart-summary-cards', 'children'),
            [Input('filtered-data', 'data'),
             Input('filter-stats', 'data')],
            [State('raw-data', 'data')]
        )
        def update_smart_summary(filtered_data, filter_stats_data, raw_data):
            if not raw_data:
                return []

            # Usar dados filtrados se disponíveis, senão usar dados brutos
            data_to_use = filtered_data if filtered_data else {'data': raw_data['data']}
            df = pd.DataFrame(data_to_use['data'])

            return self.create_smart_summary_cards(df, filter_stats_data or {})

        # Callback para gráficos principais
        @dash_app.callback(
            Output('main-chart-content', 'children'),
            [Input('main-tabs', 'active_tab'),
             Input('filtered-data', 'data')],
            [State('raw-data', 'data')]
        )
        def update_main_charts(active_tab, filtered_data, raw_data):
            if not raw_data:
                return self.create_no_data_message()

            # Usar dados filtrados se disponíveis
            data_to_use = filtered_data if filtered_data else {'data': raw_data['data']}
            df = pd.DataFrame(data_to_use['data'])

            if df.empty:
                return self.create_no_data_message("Nenhum dado encontrado com os filtros aplicados")

            if active_tab == "tab-overview":
                return self.create_overview_charts(df)
            elif active_tab == "tab-banco":
                return self.create_banco_analysis_charts(df)
            elif active_tab == "tab-categoria":
                return self.create_categoria_analysis_charts(df)
            elif active_tab == "tab-forma":
                return self.create_forma_analysis_charts(df)
            elif active_tab == "tab-trends":
                return self.create_trend_analysis_charts(df)
            elif active_tab == "tab-distributions":
                return self.create_distribution_charts(df)

        # Callback para tabela de dados
        @dash_app.callback(
            [Output('data-table-container', 'children'),
             Output('table-info', 'children')],
            [Input('filtered-data', 'data')],
            [State('raw-data', 'data')]
        )
        def update_data_table(filtered_data, raw_data):
            if not raw_data:
                return self.create_no_data_message(), ""

            data_to_use = filtered_data if filtered_data else {'data': raw_data['data']}
            df = pd.DataFrame(data_to_use['data'])

            info_text = f"Mostrando {len(df):,} registros"
            if filtered_data and filtered_data.get('filtered'):
                info_text += f" de {filtered_data.get('original_count', 0):,} total"

            return self.create_enhanced_data_table(df), info_text

        # Callback para mostrar filtros ativos
        @dash_app.callback(
            Output('active-filters-display', 'children'),
            [Input('filtered-data', 'data')],
            [State('raw-data', 'data')]
        )
        def display_active_filters(filtered_data, raw_data):
            if not raw_data or not filtered_data:
                return ""
            
            if not filtered_data.get('filtered', False):
                return dbc.Alert("🔵 Nenhum filtro ativo - mostrando todos os dados", color="info", className="py-2 mb-0 small")
            
            original_count = filtered_data.get('original_count', 0)
            filtered_count = filtered_data.get('filtered_count', 0)
            percentage = (filtered_count / original_count * 100) if original_count > 0 else 0
            
            filter_info = [
                dbc.Badge([
                    html.I(className="fas fa-filter me-1"),
                    f"Filtro Ativo: {filtered_count:,} de {original_count:,} registros ({percentage:.1f}%)"
                ], color="warning", className="me-2"),
                dbc.Badge([
                    html.I(className="fas fa-chart-bar me-1"),
                    f"Redução: {original_count - filtered_count:,} registros"
                ], color="info")
            ]
            
            return html.Div(filter_info, className="d-flex flex-wrap")

        # Callback para toggle de filtros
        @dash_app.callback(
            [Output('collapse-filters', 'is_open'),
             Output('toggle-filters', 'children')],
            [Input('toggle-filters', 'n_clicks')],
            [State('collapse-filters', 'is_open')]
        )
        def toggle_filters(n, is_open):
            if n:
                new_state = not is_open
                button_text = [
                    html.I(className=f"fas fa-chevron-{'up' if new_state else 'down'} me-1"),
                    "Recolher" if new_state else "Expandir"
                ]
                return new_state, button_text
            return is_open, [html.I(className="fas fa-chevron-down me-1"), "Expandir"]

    # =====================================================
    # MÉTODOS DE PROCESSAMENTO DE DADOS
    # =====================================================

    def process_file(self, file_path):
        try:
            file_path = Path(file_path)
            ext = file_path.suffix.lower()

            if ext in ['.xlsx', '.xls']:
                df = pd.read_excel(file_path, engine='openpyxl')
            elif ext == '.csv':
                df = self.smart_csv_read(file_path)
            elif ext == '.txt':
                df = pd.read_csv(file_path, sep='\t', encoding='utf-8')
            elif ext == '.json':
                df = pd.read_json(file_path)
            else:
                raise ValueError(f"Formato não suportado: {ext}")

            df = self.advanced_data_cleaning(df)
            stats_data = self.calculate_comprehensive_statistics(df)

            logger.info(f"Arquivo processado: {len(df)} registros, {len(df.columns)} colunas")
            return df, stats_data

        except Exception as e:
            logger.error(f"Erro ao processar arquivo: {e}")
            raise

    def smart_csv_read(self, file_path):
        encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
        separators = [',', ';', '\t', '|']

        for encoding in encodings:
            for sep in separators:
                try:
                    df = pd.read_csv(file_path, sep=sep, encoding=encoding, on_bad_lines='skip')
                    if len(df.columns) > 1 and not df.empty:
                        return df
                except Exception:
                    continue

        # Fallback
        try:
            return pd.read_csv(file_path, on_bad_lines='skip')
        except Exception as e:
            logger.error(f"Falha ao ler CSV: {e}")
            return pd.DataFrame()

    def advanced_data_cleaning(self, df):
        # Remover linhas vazias
        df = df.dropna(how='all').reset_index(drop=True)

        # Processar valores monetários
        value_columns = [col for col in df.columns if isinstance(col, str) and any(keyword in col.lower()
                                                       for keyword in ['valor', 'pago', 'receita', 'custo', 'preco'])]

        for col in value_columns:
            if df[col].dtype == 'object' or pd.api.types.is_string_dtype(df[col]):
                 df[f'{col}_Numerico'] = df[col].apply(self.clean_currency_value)
            elif pd.api.types.is_numeric_dtype(df[col]):
                 df[f'{col}_Numerico'] = df[col]

        # Processar datas
        date_columns = [col for col in df.columns if isinstance(col, str) and any(keyword in col.lower()
                                                      for keyword in ['data', 'date'])]

        for col in date_columns:
            try:
                df[col] = pd.to_datetime(df[col], errors='coerce', dayfirst=True)
                if df[col].isnull().all():
                    df[col] = pd.to_datetime(df[col], errors='coerce')
            except Exception as e:
                logger.warning(f"Não foi possível converter a coluna '{col}' para datetime: {e}")
                continue

        # Padronizar texto
        text_columns = df.select_dtypes(include=['object']).columns
        for col in text_columns:
            if not pd.api.types.is_datetime64_any_dtype(df[col]):
                try:
                    df[col] = df[col].astype(str).str.strip().str.title()
                except Exception as e:
                    logger.warning(f"Erro ao padronizar coluna de texto '{col}': {e}")
                    continue

        return df

    def clean_currency_value(self, value):
        if pd.isna(value) or value == '':
            return 0.0

        if isinstance(value, (int, float)):
            return float(value)

        value_str = str(value).strip()
        is_negative = any(indicator in value_str for indicator in ['-', '(', 'negativo'])

        # Remover R$, espaços e outros caracteres não numéricos
        value_str = value_str.replace('R$', '').replace(' ', '').replace('(', '-').replace(')', '')

        import re
        match = re.search(r'(-?[\d.,]+)', value_str)
        if not match:
            return 0.0
        clean_str = match.group(1)

        # Tratar diferentes formatos de milhar e decimal
        if ',' in clean_str and '.' in clean_str:
            if clean_str.rfind('.') < clean_str.rfind(','):
                clean_str = clean_str.replace('.', '').replace(',', '.')
            else:
                clean_str = clean_str.replace(',', '')
        elif ',' in clean_str:
            clean_str = clean_str.replace(',', '.')

        try:
            result = float(clean_str)
            return -abs(result) if is_negative and result > 0 else result
        except ValueError:
            return 0.0

    def calculate_comprehensive_statistics(self, df):
        stats_data = {
            'total_records': len(df),
            'total_columns': len(df.columns),
            'memory_usage': df.memory_usage(deep=True).sum()
        }

        # Encontrar coluna de valores principal
        value_col = self.find_main_value_column(df)

        if value_col and not df.empty:
            values = df[value_col].dropna()
            if not values.empty:
                stats_data.update({
                    'total_value': values.sum(),
                    'avg_value': values.mean(),
                    'median_value': values.median(),
                    'max_value': values.max(),
                    'min_value': values.min(),
                    'std_value': values.std(),
                    'positive_count': (values > 0).sum(),
                    'negative_count': (values < 0).sum(),
                    'zero_count': (values == 0).sum()
                })

        # Análise categórica
        categorical_analysis = {}
        for col_name in ['Tipo Banco', 'Categoria', 'Forma de Recebimento']:
            if col_name in df.columns:
                value_counts = df[col_name].value_counts().head(10)
                categorical_analysis[col_name] = {
                    'unique_count': df[col_name].nunique(),
                    'top_values': value_counts.to_dict(),
                    'null_count': df[col_name].isnull().sum()
                }

        stats_data['categorical_analysis'] = categorical_analysis

        # Análise temporal
        date_cols = [col for col in df.columns if pd.api.types.is_datetime64_any_dtype(df[col])]
        if date_cols:
            date_col = date_cols[0]
            date_values = df[date_col].dropna()
            if not date_values.empty:
                try:
                    records_by_month = df.groupby(date_values.dt.to_period('M')).size()
                    records_by_month_serializable = {str(period): count for period, count in records_by_month.items()}

                    stats_data['date_analysis'] = {
                        'date_range_start': date_values.min().isoformat(),
                        'date_range_end': date_values.max().isoformat(),
                        'date_span_days': (date_values.max() - date_values.min()).days,
                        'records_by_month': records_by_month_serializable
                    }
                except Exception as e:
                    logger.warning(f"Erro ao agrupar por mês: {e}")
                    stats_data['date_analysis'] = {}

        return stats_data

    def find_main_value_column(self, df):
        # Priorizar colunas '_Numerico'
        numeric_cols = [col for col in df.columns if isinstance(col, str) and '_Numerico' in col and pd.api.types.is_numeric_dtype(df[col])]
        if numeric_cols:
            return numeric_cols[0]

        # Fallback para outras colunas numéricas
        potential_value_cols = [
            col for col in df.select_dtypes(include=[np.number]).columns
            if isinstance(col, str) and not any(id_keyword in col.lower() for id_keyword in ['id', 'codigo', 'cod', 'numero'])
               and any(value_keyword in col.lower() for value_keyword in ['valor', 'montante', 'total', 'receita', 'custo', 'preco', 'pago'])
        ]
        if potential_value_cols:
            return potential_value_cols[0]

        general_numeric_cols = [
            col for col in df.select_dtypes(include=[np.number]).columns
            if isinstance(col, str) and not any(id_keyword in col.lower() for id_keyword in ['id', 'user_id', 'file_id', 'codigo', 'cod'])
        ]
        return general_numeric_cols[0] if general_numeric_cols else None

    def apply_enhanced_smart_filters(self, df, trigger_id, banco_filter, categoria_filter, forma_filter, valor_filter, start_date, end_date):
        """Método melhorado para aplicar filtros inteligentes com mais opções de data"""
        filtered_df = df.copy()

        # Filtros rápidos por data MELHORADOS
        date_cols = [col for col in filtered_df.columns if pd.api.types.is_datetime64_any_dtype(filtered_df[col])]

        if date_cols and trigger_id.startswith('btn-'):
            date_col_to_filter = date_cols[0]
            today = datetime.now().date()
            
            # Filtros básicos de data
            if trigger_id == 'btn-hoje':
                filtered_df = filtered_df[filtered_df[date_col_to_filter].dt.date == today]
                
            elif trigger_id == 'btn-ontem':
                yesterday = today - timedelta(days=1)
                filtered_df = filtered_df[filtered_df[date_col_to_filter].dt.date == yesterday]
                
            # Filtros de semana
            elif trigger_id == 'btn-esta-semana':
                # Segunda-feira desta semana até hoje
                start_of_week = today - timedelta(days=today.weekday())  # Segunda-feira
                filtered_df = filtered_df[
                    (filtered_df[date_col_to_filter].dt.date >= start_of_week) & 
                    (filtered_df[date_col_to_filter].dt.date <= today)
                ]
                
            elif trigger_id == 'btn-semana-passada':
                # Segunda a domingo da semana passada
                start_last_week = today - timedelta(days=today.weekday() + 7)  # Segunda da semana passada
                end_last_week = start_last_week + timedelta(days=6)  # Domingo da semana passada
                filtered_df = filtered_df[
                    (filtered_df[date_col_to_filter].dt.date >= start_last_week) & 
                    (filtered_df[date_col_to_filter].dt.date <= end_last_week)
                ]
                
            # Filtros de período (últimos N dias)
            elif trigger_id == 'btn-7dias':
                date_7_ago = today - timedelta(days=7)
                filtered_df = filtered_df[
                    (filtered_df[date_col_to_filter].dt.date >= date_7_ago) & 
                    (filtered_df[date_col_to_filter].dt.date <= today)
                ]
                
            elif trigger_id == 'btn-15dias':
                date_15_ago = today - timedelta(days=15)
                filtered_df = filtered_df[
                    (filtered_df[date_col_to_filter].dt.date >= date_15_ago) & 
                    (filtered_df[date_col_to_filter].dt.date <= today)
                ]
                
            elif trigger_id == 'btn-30dias':
                date_30_ago = today - timedelta(days=30)
                filtered_df = filtered_df[
                    (filtered_df[date_col_to_filter].dt.date >= date_30_ago) & 
                    (filtered_df[date_col_to_filter].dt.date <= today)
                ]
                
            elif trigger_id == 'btn-90dias':
                date_90_ago = today - timedelta(days=90)
                filtered_df = filtered_df[
                    (filtered_df[date_col_to_filter].dt.date >= date_90_ago) & 
                    (filtered_df[date_col_to_filter].dt.date <= today)
                ]
                
            # Filtros de mês
            elif trigger_id == 'btn-este-mes':
                # Primeiro dia do mês atual até hoje
                first_day_current_month = today.replace(day=1)
                filtered_df = filtered_df[
                    (filtered_df[date_col_to_filter].dt.date >= first_day_current_month) & 
                    (filtered_df[date_col_to_filter].dt.date <= today)
                ]
                
            elif trigger_id == 'btn-mes-passado':
                # Todo o mês passado
                if today.month == 1:
                    last_month = 12
                    last_year = today.year - 1
                else:
                    last_month = today.month - 1
                    last_year = today.year
                    
                first_day_last_month = datetime(last_year, last_month, 1).date()
                last_day_last_month = (datetime(last_year, last_month, calendar.monthrange(last_year, last_month)[1])).date()
                
                filtered_df = filtered_df[
                    (filtered_df[date_col_to_filter].dt.date >= first_day_last_month) & 
                    (filtered_df[date_col_to_filter].dt.date <= last_day_last_month)
                ]
                
            elif trigger_id == 'btn-este-ano':
                # Primeiro dia do ano até hoje
                first_day_year = datetime(today.year, 1, 1).date()
                filtered_df = filtered_df[
                    (filtered_df[date_col_to_filter].dt.date >= first_day_year) & 
                    (filtered_df[date_col_to_filter].dt.date <= today)
                ]
                
            # Filtros por dia da semana (0 = Segunda, 6 = Domingo)
            elif trigger_id == 'btn-segunda':
                filtered_df = filtered_df[filtered_df[date_col_to_filter].dt.weekday == 0]
            elif trigger_id == 'btn-terca':
                filtered_df = filtered_df[filtered_df[date_col_to_filter].dt.weekday == 1]
            elif trigger_id == 'btn-quarta':
                filtered_df = filtered_df[filtered_df[date_col_to_filter].dt.weekday == 2]
            elif trigger_id == 'btn-quinta':
                filtered_df = filtered_df[filtered_df[date_col_to_filter].dt.weekday == 3]
            elif trigger_id == 'btn-sexta':
                filtered_df = filtered_df[filtered_df[date_col_to_filter].dt.weekday == 4]
            elif trigger_id == 'btn-sabado':
                filtered_df = filtered_df[filtered_df[date_col_to_filter].dt.weekday == 5]
            elif trigger_id == 'btn-domingo':
                filtered_df = filtered_df[filtered_df[date_col_to_filter].dt.weekday == 6]

        # Filtros personalizados (mesmo código anterior)
        if trigger_id == 'apply-filters':
            # Filtro por banco
            if banco_filter and 'Tipo Banco' in filtered_df.columns:
                filtered_df = filtered_df[filtered_df['Tipo Banco'].isin(banco_filter)]

            # Filtro por categoria
            if categoria_filter and 'Categoria' in filtered_df.columns:
                filtered_df = filtered_df[filtered_df['Categoria'].isin(categoria_filter)]

            # Filtro por forma
            if forma_filter and 'Forma de Recebimento' in filtered_df.columns:
                filtered_df = filtered_df[filtered_df['Forma de Recebimento'].isin(forma_filter)]

            # Filtro por valor
            if valor_filter:
                value_col_to_filter = self.find_main_value_column(filtered_df)
                if value_col_to_filter:
                    filtered_df = filtered_df[
                        (filtered_df[value_col_to_filter] >= valor_filter[0]) &
                        (filtered_df[value_col_to_filter] <= valor_filter[1])
                    ]

            # Filtro por data personalizada
            if start_date and end_date and date_cols:
                date_col_to_filter_custom = date_cols[0]
                try:
                    start_date_dt = pd.to_datetime(start_date).date()
                    end_date_dt = pd.to_datetime(end_date).date()

                    filtered_df = filtered_df[
                        (filtered_df[date_col_to_filter_custom].dt.date >= start_date_dt) &
                        (filtered_df[date_col_to_filter_custom].dt.date <= end_date_dt)
                    ]
                except Exception as e:
                    logger.warning(f"Erro ao aplicar filtro de data: {e}")

        return filtered_df

    def calculate_filter_statistics(self, filtered_df, original_df):
        value_col = self.find_main_value_column(filtered_df)

        stats_data = {
            'total_filtered': len(filtered_df),
            'total_original': len(original_df),
            'filter_percentage': (len(filtered_df) / len(original_df)) * 100 if len(original_df) > 0 else 0
        }

        if value_col and not filtered_df.empty:
            values = filtered_df[value_col].dropna()
            if not values.empty:
                stats_data.update({
                    'filtered_total_value': values.sum(),
                    'filtered_avg_value': values.mean(),
                    'filtered_positive_count': (values > 0).sum(),
                    'filtered_negative_count': (values < 0).sum()
                })

                # Comparação com dados originais
                original_values = original_df[value_col].dropna()
                if not original_values.empty:
                    original_sum = original_values.sum()
                    original_mean = original_values.mean()
                    if original_sum != 0:
                         stats_data['value_change_percentage'] = ((values.sum() - original_sum) / original_sum) * 100
                    else:
                         stats_data['value_change_percentage'] = 0

                    if original_mean != 0:
                        stats_data['avg_change_percentage'] = ((values.mean() - original_mean) / original_mean) * 100
                    else:
                        stats_data['avg_change_percentage'] = 0

        return stats_data

    # =====================================================
    # MÉTODOS DE CRIAÇÃO DE GRÁFICOS
    # =====================================================

    def create_overview_charts(self, df):
        """Criar visão geral com múltiplos gráficos"""
        colors = COLOR_PALETTES['prima_arena']
        value_col = self.find_main_value_column(df)
        charts = []

        if not value_col or df.empty:
            return self.create_no_data_message("Coluna de valores não encontrada")

        # 1. Gráfico de Pizza - Distribuição por Categoria
        if 'Categoria' in df.columns:
            categoria_data = df.groupby('Categoria')[value_col].agg(['sum', 'count']).reset_index()
            categoria_data.columns = ['Categoria', 'Valor_Total', 'Quantidade']
            categoria_data_positive = categoria_data[categoria_data['Valor_Total'] > 0]

            if not categoria_data_positive.empty:
                fig_pie = px.pie(
                    categoria_data_positive,
                    values='Valor_Total',
                    names='Categoria',
                    title="Distribuição de Valores por Categoria",
                    color_discrete_sequence=colors,
                    hole=0.4
                )

                fig_pie.update_traces(
                    textposition='inside',
                    textinfo='percent+label',
                    hovertemplate='<b>%{label}</b><br>' +
                                  'Valor: R$ %{value:,.0f}<br>' +
                                  'Percentual: %{percent}<extra></extra>'
                )

                fig_pie.update_layout(height=450, title_x=0.5)
                charts.append(dbc.Col([dcc.Graph(figure=fig_pie)], md=6))

        # 2. Gráfico de Barras - Banco vs Valor
        if 'Tipo Banco' in df.columns:
            banco_data = df.groupby('Tipo Banco')[value_col].agg(['sum', 'mean', 'count']).reset_index()
            banco_data.columns = ['Banco', 'Total', 'Media', 'Quantidade']
            banco_data = banco_data.sort_values('Total', ascending=False)

            if not banco_data.empty:
                fig_bar = make_subplots(
                    rows=1, cols=1,
                    secondary_y=True,
                    subplot_titles=["Análise por Banco"]
                )

                fig_bar.add_trace(
                    go.Bar(
                        x=banco_data['Banco'],
                        y=banco_data['Total'],
                        name='Valor Total',
                        marker=dict(color=colors[0]),
                        text=[f'R$ {v:,.0f}' for v in banco_data['Total']],
                        textposition='outside'
                    ),
                    secondary_y=False
                )

                fig_bar.add_trace(
                    go.Scatter(
                        x=banco_data['Banco'],
                        y=banco_data['Media'],
                        mode='lines+markers',
                        name='Valor Médio',
                        line=dict(color=colors[1], width=3),
                        marker=dict(size=8)
                    ),
                    secondary_y=True
                )

                fig_bar.update_xaxes(title_text="Banco", tickangle=-45)
                fig_bar.update_yaxes(title_text="Valor Total (R$)", secondary_y=False)
                fig_bar.update_yaxes(title_text="Valor Médio (R$)", secondary_y=True)
                fig_bar.update_layout(height=450, hovermode='x unified')

                charts.append(dbc.Col([dcc.Graph(figure=fig_bar)], md=6))

        if not charts:
            return self.create_no_data_message("Dados insuficientes para visão geral")
        return dbc.Row(charts)

    def create_banco_analysis_charts(self, df):
        if 'Tipo Banco' not in df.columns:
            return self.create_no_data_message("Coluna 'Tipo Banco' não encontrada")

        colors = COLOR_PALETTES['analise']
        value_col = self.find_main_value_column(df)
        charts = []

        if not value_col or df.empty:
             return self.create_no_data_message("Dados insuficientes para análise por banco")

        # Análise de Quantidade por Banco
        banco_counts_data = df['Tipo Banco'].value_counts().reset_index()
        banco_counts_data.columns = ['Tipo Banco', 'Quantidade']
        banco_counts_data = banco_counts_data.sort_values(by='Quantidade', ascending=False)

        if not banco_counts_data.empty:
            fig_qty = go.Figure(data=[go.Bar(
                x=banco_counts_data['Quantidade'],
                y=banco_counts_data['Tipo Banco'],
                orientation='h',
                marker=dict(color=colors[0]),
                text=banco_counts_data['Quantidade'],
                textposition='outside'
            )])

            fig_qty.update_layout(
                title="Quantidade de Transações por Banco",
                title_x=0.5,
                height=max(400, len(banco_counts_data) * 30),
                xaxis_title="Quantidade de Transações",
                yaxis_title="Tipo de Banco",
                yaxis=dict(autorange="reversed")
            )
            charts.append(dbc.Col([dcc.Graph(figure=fig_qty)], md=6))

        # Análise de Valores por Banco
        banco_values_data = df.groupby('Tipo Banco')[value_col].agg(['sum', 'mean', 'count']).round(2).reset_index()
        banco_values_data.columns = ['Tipo Banco', 'Total', 'Média', 'Quantidade']
        banco_values_data = banco_values_data.sort_values(by='Total', ascending=False)

        if not banco_values_data.empty:
            fig_values = go.Figure()

            fig_values.add_trace(go.Bar(
                name='Valor Total',
                x=banco_values_data['Tipo Banco'],
                y=banco_values_data['Total'],
                marker=dict(color=colors[1]),
                yaxis='y1'
            ))

            fig_values.add_trace(go.Scatter(
                name='Valor Médio',
                x=banco_values_data['Tipo Banco'],
                y=banco_values_data['Média'],
                mode='lines+markers',
                marker=dict(color=colors[2], size=8),
                yaxis='y2',
                line=dict(width=3)
            ))

            fig_values.update_layout(
                title="Análise de Valores por Banco",
                title_x=0.5,
                height=max(400, len(banco_values_data) * 30),
                xaxis_title="Tipo de Banco",
                yaxis=dict(title="Valor Total (R$)", side="left", showgrid=False),
                yaxis2=dict(title="Valor Médio (R$)", side="right", overlaying="y", showgrid=True, gridcolor='lightgrey'),
                legend=dict(x=0.01, y=0.99, bordercolor="Black", borderwidth=1)
            )
            charts.append(dbc.Col([dcc.Graph(figure=fig_values)], md=6))

        if not charts:
            return self.create_no_data_message("Dados insuficientes para análise por banco")
        return dbc.Row(charts)

    def create_categoria_analysis_charts(self, df):
        if 'Categoria' not in df.columns:
            return self.create_no_data_message("Coluna 'Categoria' não encontrada")

        colors = COLOR_PALETTES['financeiro']
        value_col = self.find_main_value_column(df)
        charts = []

        if not value_col or df.empty:
             return self.create_no_data_message("Dados insuficientes para análise por categoria")

        # Treemap - Proporção de Valores por Categoria
        categoria_values_sum = df.groupby('Categoria')[value_col].sum().reset_index()
        categoria_values_sum = categoria_values_sum[categoria_values_sum[value_col] > 0]
        categoria_values_sum = categoria_values_sum.sort_values(by=value_col, ascending=False)

        if not categoria_values_sum.empty:
            fig_treemap = go.Figure(go.Treemap(
                labels=categoria_values_sum['Categoria'],
                values=categoria_values_sum[value_col],
                parents=[''] * len(categoria_values_sum),
                textinfo="label+value+percent root",
                texttemplate="<b>%{label}</b><br>R$ %{value:,.0f}<br>%{percentRoot:.1f}%",
                marker=dict(colors=colors, colorscale='Blues'),
                branchvalues="total"
            ))

            fig_treemap.update_layout(
                title="Mapa de Valores por Categoria",
                title_x=0.5,
                height=500,
                margin=dict(t=50, l=25, r=25, b=25)
            )
            charts.append(dbc.Col([dcc.Graph(figure=fig_treemap)], md=12))

        if not charts:
            return self.create_no_data_message("Dados insuficientes para análise por categoria")
        return dbc.Row(charts)

    def create_forma_analysis_charts(self, df):
        if 'Forma de Recebimento' not in df.columns:
            return self.create_no_data_message("Coluna 'Forma de Recebimento' não encontrada")

        colors = COLOR_PALETTES['moderno']
        value_col = self.find_main_value_column(df)
        charts = []

        if df.empty:
             return self.create_no_data_message("Dados insuficientes para análise por forma")

        # Gráfico de Barras Horizontais
        forma_counts_data = df['Forma de Recebimento'].value_counts().reset_index()
        forma_counts_data.columns = ['Forma de Recebimento', 'Quantidade']
        forma_counts_data = forma_counts_data.sort_values(by='Quantidade', ascending=True)

        if not forma_counts_data.empty:
            fig_horizontal = go.Figure(go.Bar(
                x=forma_counts_data['Quantidade'],
                y=forma_counts_data['Forma de Recebimento'],
                orientation='h',
                marker=dict(color=colors, line=dict(color='black', width=0.5)),
                text=forma_counts_data['Quantidade'],
                textposition='outside'
            ))

            fig_horizontal.update_layout(
                title="Quantidade por Forma de Recebimento",
                title_x=0.5,
                height=max(300, len(forma_counts_data) * 35),
                xaxis_title="Quantidade de Transações",
                yaxis_title="Forma de Recebimento",
                margin=dict(l=150)
            )
            charts.append(dbc.Col([dcc.Graph(figure=fig_horizontal)], md=12))

        if not charts:
            return self.create_no_data_message("Dados insuficientes para análise por forma")
        return dbc.Row(charts)

    def create_trend_analysis_charts(self, df):
        date_cols = [col for col in df.columns if pd.api.types.is_datetime64_any_dtype(df[col])]
        value_col = self.find_main_value_column(df)

        if not date_cols or not value_col:
            return self.create_no_data_message("Dados de data ou valores não encontrados")

        date_col = date_cols[0]
        df_clean = df.dropna(subset=[date_col, value_col]).copy()

        if df_clean.empty:
            return self.create_no_data_message("Dados insuficientes para análise de tendência")

        colors = COLOR_PALETTES['prima_arena']
        charts = []

        df_clean.sort_values(by=date_col, inplace=True)

        # Agregação diária
        daily_data = df_clean.groupby(df_clean[date_col].dt.date)[value_col].agg(['sum', 'count', 'mean']).reset_index()
        daily_data.columns = ['Data', 'Valor_Total', 'Quantidade', 'Valor_Medio']

        if not daily_data.empty:
            fig_trend = go.Figure()

            fig_trend.add_trace(go.Scatter(
                x=daily_data['Data'],
                y=daily_data['Valor_Total'],
                mode='lines+markers',
                name='Valor Total Diário',
                line=dict(color=colors[0], width=2),
                marker=dict(size=5)
            ))

            # Média móvel de 7 dias
            if len(daily_data) >= 7:
                daily_data['MA7_Valor'] = daily_data['Valor_Total'].rolling(window=7, min_periods=1, center=True).mean()
                fig_trend.add_trace(go.Scatter(
                    x=daily_data['Data'],
                    y=daily_data['MA7_Valor'],
                    mode='lines',
                    name='Média Móvel 7 dias',
                    line=dict(color=colors[1], width=2, dash='dash')
                ))

            fig_trend.update_layout(
                title="Tendência de Valores Diários",
                title_x=0.5,
                height=450,
                xaxis_title="Data",
                yaxis_title=f"Valor ({CONFIG.get('CURRENCY_SYMBOL', 'R$')})",
                hovermode='x unified'
            )
            charts.append(dbc.Col([dcc.Graph(figure=fig_trend)], md=12))

        if not charts:
            return self.create_no_data_message("Não foi possível gerar gráficos de tendência")
        return dbc.Row(charts)

    def create_distribution_charts(self, df):
        value_col = self.find_main_value_column(df)

        if not value_col or df.empty:
            return self.create_no_data_message("Dados insuficientes para análise de distribuição")

        colors = COLOR_PALETTES['analise']
        charts = []
        values = df[value_col].dropna()

        if values.empty:
            return self.create_no_data_message("Nenhum valor para análise")

        # Histograma de Valores
        num_bins = min(max(10, int(len(values)/10)), 50)

        fig_hist = go.Figure(data=[go.Histogram(
            x=values,
            nbinsx=num_bins,
            marker=dict(color=colors[0], opacity=0.75, line=dict(color='black', width=0.5)),
            name='Distribuição'
        )])

        fig_hist.update_layout(
            title="Histograma da Distribuição de Valores",
            title_x=0.5,
            height=450,
            xaxis_title=f"Valor ({CONFIG.get('CURRENCY_SYMBOL', 'R$')})",
            yaxis_title="Frequência",
            bargap=0.1
        )
        charts.append(dbc.Col([dcc.Graph(figure=fig_hist)], md=12))

        if not charts:
            return self.create_no_data_message("Dados insuficientes para distribuição")
        return dbc.Row(charts)

    def create_smart_summary_cards(self, df, filter_stats_data):
        value_col = self.find_main_value_column(df)
        cards_list = []

        # Card 1: Total de Registros
        total_records = len(df)
        original_records = filter_stats_data.get('total_original', total_records)

        cards_list.append(
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        dbc.Row([
                            dbc.Col(html.I(className="fas fa-database fa-2x text-primary mb-2"), width="auto", className="align-self-center"),
                            dbc.Col([
                                html.H4(f"{total_records:,}", className="text-primary fw-bold mb-0"),
                                html.P("Registros Visíveis", className="text-muted mb-0 small"),
                                html.Small(f"de {original_records:,} total ({(total_records/original_records*100) if original_records > 0 else 0:.1f}%)"
                                           if total_records != original_records else "total (100%)",
                                           className="text-info small")
                            ])
                        ])
                    ])
                ], className="h-100 shadow-sm border-0", style={"border-left": "5px solid #0d6efd !important"})
            ], md=3, className="mb-3")
        )

        # Card 2: Valor Total
        if value_col and not df.empty:
            total_value = df[value_col].sum()
            avg_value = df[value_col].mean() if not df.empty else 0

            cards_list.append(
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            dbc.Row([
                                dbc.Col(html.I(className="fas fa-money-bill-wave fa-2x text-success mb-2"), width="auto", className="align-self-center"),
                                dbc.Col([
                                    html.H4(f"{CONFIG.get('CURRENCY_SYMBOL', 'R$')} {total_value:,.2f}", className="text-success fw-bold mb-0"),
                                    html.P("Valor Total Visível", className="text-muted mb-0 small"),
                                    html.Small(f"Média: {CONFIG.get('CURRENCY_SYMBOL', 'R$')} {avg_value:,.2f}", className="text-info small")
                                ])
                            ])
                        ])
                    ], className="h-100 shadow-sm border-0", style={"border-left": "5px solid #198754 !important"})
                ], md=3, className="mb-3")
            )

            # Card 3: Positivos vs Negativos
            positive_count = (df[value_col] > 0).sum()
            negative_count = (df[value_col] < 0).sum()
            total_pos_neg = positive_count + negative_count

            cards_list.append(
                dbc.Col([
                    dbc.Card([
                        dbc.CardBody([
                            dbc.Row([
                                dbc.Col(html.I(className="fas fa-exchange-alt fa-2x text-info mb-2"), width="auto", className="align-self-center"),
                                dbc.Col([
                                    html.H6(f"Pos: {positive_count:,} | Neg: {negative_count:,}", className="text-info fw-bold mb-1"),
                                    html.P("Trans. Positivas vs Negativas", className="text-muted mb-0 small"),
                                    html.Small(f"{(positive_count/total_pos_neg*100):.1f}% positivas"
                                               if total_pos_neg > 0 else "N/A", className="text-primary small")
                                ])
                            ])
                        ])
                    ], className="h-100 shadow-sm border-0", style={"border-left": "5px solid #0dcaf0 !important"})
                ], md=3, className="mb-3")
            )

        # Card 4: Filtros Ativos
        filter_percentage = filter_stats_data.get('filter_percentage', 100)

        cards_list.append(
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        dbc.Row([
                            dbc.Col(html.I(className="fas fa-filter fa-2x text-warning mb-2"), width="auto", className="align-self-center"),
                            dbc.Col([
                                html.H4(f"{filter_percentage:.1f}%", className="text-warning fw-bold mb-0"),
                                html.P("Dados Visíveis (Filtro)", className="text-muted mb-0 small"),
                                html.Small("Filtros aplicados" if filter_percentage < 100 else "Sem filtros ativos",
                                           className="text-secondary small")
                            ])
                        ])
                    ])
                ], className="h-100 shadow-sm border-0", style={"border-left": "5px solid #ffc107 !important"})
            ], md=3, className="mb-3")
        )

        return cards_list

    def create_enhanced_data_table(self, df):
        # Preparar colunas com formatação específica
        columns = []
        df_display = df.copy()

        for col_name in df_display.columns:
            col_config = {"name": str(col_name).replace('_', ' ').title(), "id": col_name}

            # Formatação para colunas numéricas
            if pd.api.types.is_numeric_dtype(df_display[col_name]):
                is_currency = '_Numerico' in str(col_name) or \
                              any(keyword in str(col_name).lower() for keyword in ['valor', 'pago', 'receita', 'custo', 'preco', 'total'])

                if is_currency:
                    col_config.update({
                        "type": "numeric",
                        "format": dash_table.Format.Format(precision=2, scheme=dash_table.Format.Scheme.fixed).group(True),
                    })
                else:
                    is_percentage = 'perc' in str(col_name).lower() or '%' in str(col_name)
                    if is_percentage:
                         col_config.update({
                            "type": "numeric",
                            "format": dash_table.Format.Format(precision=2, scheme=dash_table.Format.Scheme.percentage)
                         })
                    else:
                        col_config.update({
                            "type": "numeric",
                             "format": dash_table.Format.Format(precision=0, scheme=dash_table.Format.Scheme.fixed).group(True) if df_display[col_name].apply(lambda x: x == int(x) if pd.notnull(x) else True).all() else dash_table.Format.Format(precision=2, scheme=dash_table.Format.Scheme.fixed).group(True)
                        })

            # Formatação para colunas de data/hora
            elif pd.api.types.is_datetime64_any_dtype(df_display[col_name]):
                col_config.update({"type": "datetime"})
                try:
                    df_display[col_name] = pd.to_datetime(df_display[col_name]).dt.strftime('%d/%m/%Y %H:%M:%S')
                except Exception:
                     df_display[col_name] = pd.to_datetime(df_display[col_name]).dt.strftime('%d/%m/%Y')

            columns.append(col_config)

        return dash_table.DataTable(
            data=df_display.head(1000).to_dict('records'),
            columns=columns,
            page_size=15,
            filter_action="native",
            sort_action="native",
            sort_mode="multi",
            column_selectable="single",
            row_selectable="multi",
            selected_columns=[],
            selected_rows=[],
            export_format="xlsx",
            export_headers="display",
            style_table={
                'overflowX': 'auto',
                'border': '1px solid #ddd',
                'borderCollapse': 'collapse'
            },
            style_header={
                'backgroundColor': '#f0f0f0',
                'color': '#333',
                'fontWeight': 'bold',
                'textAlign': 'left',
                'border': '1px solid #ddd',
                'padding': '8px',
                'fontSize': '13px',
                'textTransform': 'capitalize'
            },
            style_cell={
                'backgroundColor': 'white',
                'color': '#444',
                'textAlign': 'left',
                'padding': '8px',
                'fontFamily': '"Segoe UI", Arial, sans-serif',
                'fontSize': '12px',
                'border': '1px solid #eee',
                'minWidth': '100px', 'width': '150px', 'maxWidth': '300px',
                'overflow': 'hidden',
                'textOverflow': 'ellipsis',
            },
            style_data_conditional=[
                {
                    'if': {'row_index': 'odd'},
                    'backgroundColor': '#f9f9f9'
                },
                {
                    'if': {'state': 'selected'},
                    'backgroundColor': 'rgba(0, 123, 255, 0.1)',
                    'border': '1px solid #007bff'
                }
            ]
        )

    def create_no_data_message(self, message="Nenhum dado disponível para visualização."):
        return dbc.Alert([
            html.Div([
                html.I(className="fas fa-info-circle fa-3x text-primary mb-3"),
                html.H5(message, className="text-primary"),
                html.P("Por favor, carregue um arquivo de dados ou ajuste os filtros aplicados.", className="text-muted small")
            ], className="text-center py-5")
        ], color="light", className="border-dashed", style={"borderColor": "#0d6efd"})

    def create_status_badge(self, text, color):
        return dbc.Badge(text, color=color, className="fs-6 p-2")

    # =====================================================
    # MÉTODOS AUXILIARES
    # =====================================================

    def allowed_file(self, filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in CONFIG['ALLOWED_EXTENSIONS']

    def get_file_options(self):
        try:
            with self.db.get_connection() as conn:
                files = conn.execute('''
                    SELECT id, original_filename, upload_date, file_size, records_count
                    FROM uploaded_files
                    ORDER BY upload_date DESC
                    LIMIT 50
                ''').fetchall()

            return [
                {
                    'label': f"{file['original_filename']} ({pd.to_datetime(file['upload_date']).strftime('%d/%m/%y %H:%M') if file['upload_date'] else 'Data N/A'} - {file['records_count'] if file['records_count'] is not None else 0:,} reg.)",
                    'value': file['id']
                }
                for file in files
            ]
        except Exception as e:
            logger.error(f"Erro ao obter arquivos: {e}")
            return []

    def get_dropdown_options(self, df, column_name):
        if column_name in df.columns:
            try:
                unique_values = sorted(df[column_name].dropna().astype(str).unique())
                return [{'label': str(val), 'value': str(val)} for val in unique_values]
            except Exception as e:
                logger.warning(f"Erro ao obter opções para dropdown da coluna '{column_name}': {e}")
                return []
        return []

    def get_value_range(self, df):
        value_col = self.find_main_value_column(df)
        if value_col and not df.empty:
            values = df[value_col].dropna()
            if not values.empty:
                min_val = float(values.min())
                max_val = float(values.max())
                return min_val, max_val if max_val >= min_val else min_val
        return 0, 100

    def get_date_range(self, df):
        date_cols = [col for col in df.columns if pd.api.types.is_datetime64_any_dtype(df[col])]
        if date_cols:
            date_col = date_cols[0]
            date_values = df[date_col].dropna()
            if not date_values.empty:
                try:
                    return date_values.min().strftime('%Y-%m-%d'), date_values.max().strftime('%Y-%m-%d')
                except Exception as e:
                    logger.warning(f"Erro ao obter range de data: {e}")
                    return None, None
        return None, None

    def run(self, debug=True, port=8050, host='0.0.0.0'):
        # Logs sem emojis para compatibilidade com Windows
        logger.info(f"Iniciando {CONFIG['APP_NAME']} v{CONFIG['VERSION']}")
        logger.info(f"Acesse em: http://{host}:{port}")
        logger.info(f"Usuarios admin configurados: {list(CONFIG['ADMIN_USERS'].keys())}")

        try:
            self.app.run(debug=debug, port=port, host=host)
        except OSError as e:
            if "address already in use" in str(e).lower():
                logger.error(f"ERRO: A porta {port} ja esta em uso.")
            else:
                logger.error(f"ERRO ao iniciar servidor: {e}")

# =====================================================
# PONTO DE ENTRADA
# =====================================================

if __name__ == '__main__':
    try:
        print("\n" + "="*70)
        print("PRIMA ARENA FINANCE SYSTEM v2.1.0 - CORRIGIDO COMPLETO")
        print("="*70)
        print("Melhorias desta versao:")
        print("   • Correcao do erro de URL do Dash")
        print("   • Correcao do erro de Unicode no Windows")
        print("   • Templates separados em arquivos fisicos")
        print("   • TODAS as funcionalidades mantidas:")
        print("     - Filtragem inteligente")
        print("     - Graficos avancados")
        print("     - Analises por banco/categoria/forma")
        print("     - Sistema de alertas")
        print("     - Exportacao de dados")
        print("     - Tabelas interativas")
        print("   • Estrutura modular preparada para Git")
        print("\nUsuarios Administrativos:")
        for u, p in CONFIG['ADMIN_USERS'].items():
            print(f"   • {u} / {p}")
        print("="*70)

        system = PrimaArenaFinanceSystem()
        system.run(debug=True, port=8050, host='0.0.0.0')

    except KeyboardInterrupt:
        print("\nSistema interrompido pelo usuario.")
    except Exception as e:
        print(f"\nERRO CRITICO: {e}")