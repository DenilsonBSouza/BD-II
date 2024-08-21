from pymongo import MongoClient

# Conectar ao MongoDB
client = MongoClient('mongodb://localhost:27017/')
db = client['reclame_aqui']
users_collection = db['users']

# Consultar um usuário específico
name = 'Denilson'
user = users_collection.find_one({'name': name})

if user:
    print(f"Usuário encontrado: {user}")
else:
    print("Usuário não encontrado")
