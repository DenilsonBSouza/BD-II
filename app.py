from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from pymongo import MongoClient
from elasticsearch import Elasticsearch
import hashlib
from datetime import datetime
import re
from werkzeug.utils import secure_filename
import os
from functools import wraps


app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Substitua por uma chave secreta real

# Conectar ao MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client['reclame_aqui']

# Conectar ao Elasticsearch
es = Elasticsearch([{'host': 'localhost', 'port': 9200}])
try:
    # Testa a conexão
    if es.ping():
        print("Conectado ao Elasticsearch com sucesso!")
    else:
        print("Falha na conexão com o Elasticsearch.")
except Exception as e:
    print(f"Erro ao conectar com Elasticsearch: {e}")

# Definir o mapeamento do índice
mapping = {
    "mappings": {
        "properties": {
            "title": {"type": "text"},
            "enterprise": {"type": "text"},
            "description": {"type": "text"},
            "date": {"type": "date"},
            "user_id": {"type": "keyword"}
        }
    }
}

# Criar o índice com o mapeamento, se ainda não existir
if not es.indices.exists(index='complaints_index'):
    es.indices.create(index='complaints_index', body=mapping)

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('complaints'))
    return redirect(url_for('login'))

# Função para garantir que o usuário está logado
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Você precisa estar logado para acessar essa página.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Validação de e-mail
def is_valid_email(email):
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email) is not None

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        if not is_valid_email(email):
            flash('Formato de e-mail inválido. Verifique e tente novamente.')
            return redirect(url_for('login'))
        
        user = db.users.find_one({'email': email})
        
        if user:
            if user['password'] == hashed_password:
                session['user_id'] = str(user['_id'])
                flash('Login realizado com sucesso!')
                return redirect(url_for('complaints'))
            else:
                flash('Senha incorreta. Tente novamente.')
        else:
            flash('E-mail não registrado.')
    
    return render_template('login.html')

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    flash('Você foi desconectado com sucesso.')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        name = request.form.get('name')
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        existing_user = db.users.find_one({'email': email})
        if existing_user:
            flash('Usuário já cadastrado. Faça login para continuar.')
            return redirect(url_for('login'))

        db.users.insert_one({'name': name, 'email': email, 'password': hashed_password})
        flash('Cadastro realizado com sucesso!')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/recover_password', methods=['GET', 'POST'])
def recover_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = db.users.find_one({'email': email})
        if user:
            flash('Instruções de recuperação de senha enviadas para o seu e-mail.')
        else:
            flash('Email não encontrado.')
        return redirect(url_for('login'))

    return render_template('recover_password.html')

@app.route('/complaints', methods=['GET', 'POST'])
@login_required
def complaints():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        user_id = session['user_id']
        
        db.complaints.insert_one({
            'user_id': user_id,
            'title': title,
            'description': description,
            'date': datetime.utcnow()
        })
        
        flash('Reclamação registrada com sucesso!')
        return redirect(url_for('complaints'))
    
    user_id = session['user_id']
    cursor = db.complaints.find({'user_id': user_id}).sort('date', -1)
    complaints = list(cursor)
    
    return render_template('complaints.html', complaints=complaints)

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf', 'jpeg', 'jpg', 'png', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@app.route('/complaint/submit', methods=['POST'])
@login_required
def submit_complaint():
    print("Request files:", request.files)  # Verifica o conteúdo dos arquivos recebidos
    
    title = request.form.get('title')
    enterprise = request.form.get('enterprise')
    description = request.form.get('description')
    user_id = session['user_id']
    
    file = request.files.get('file')
    filename = None
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        print(f"Arquivo salvo em: {file_path}")  # Verifica o caminho onde o arquivo foi salvo
    else:
        if file:
            print(f"Arquivo recebido mas não permitido: {file.filename}")
        else:
            print("Nenhum arquivo recebido.")
    
    complaint_data = {
        'user_id': user_id,
        'title': title,
        'enterprise': enterprise,
        'description': description,
        'date': datetime.utcnow(),
        'file': filename
    }
    
    try:
        complaint_id = db.complaints.insert_one(complaint_data).inserted_id
        complaint_data_for_es = {
            'title': complaint_data['title'],
            'enterprise': complaint_data['enterprise'],
            'description': complaint_data['description'],
            'date': complaint_data['date'],
            'user_id': complaint_data['user_id'],
            'file': complaint_data['file']
        }
        es.index(index='complaints_index', id=str(complaint_id), body=complaint_data_for_es)
        flash('Reclamação registrada com sucesso!')
    except Exception as e:
        flash(f'Ocorreu um erro ao registrar a reclamação: {str(e)}')
    
    return redirect(url_for('complaints'))



@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/search', methods=['GET'])
@login_required
def search():
    query = request.args.get('q')
    results = es.search(index='complaints_index', body={'query': {'match': {'description': query}}})
    return render_template('search_results.html', results=results['hits']['hits'])


if __name__ == '__main__':
    app.run(debug=False)
