from datetime import timedelta
from flask import Flask, jsonify, request
from flask_migrate import Migrate
from models import db, User
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///dataBaseUsers.db"
app.config["SECRET_KEY"] = "MI_PALABRA_SECRETA"
app.config["JWT_SECRET_KEY"] = "MI_PALABRA_SECRETA_JWT"
db.init_app(app)
CORS(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

expires_jwt = timedelta(minutes=1)

@app.route('/get_users', methods=['GET'])
@jwt_required()
def get_users():
  get_users = User().query.all()
  # [<User 1>, <User 2>, <User 3>, <User 4>, <User 5>, <User 6>, <User 7>]
  get_users_serialize = list(map(lambda user: user.serialize(), get_users))
  print(get_users_serialize)
  return jsonify({"mjs": "success", "data": get_users_serialize})

@app.route("/login", methods=['POST'])
def login():
  email = request.json.get("email")
  password = request.json.get("password")

  user_exist = User.query.filter_by(email = email).first()

  if user_exist is not None:
    if bcrypt.check_password_hash(user_exist.password, password):
      token = create_access_token(identity=email, expires_delta=expires_jwt)
      return jsonify({
        "mjs": "success",
        "data": user_exist.serialize(),
        "Token": token
      })
    else:
       return jsonify({
        "mjs": "error, email or password not found"
      })
  else:
      return jsonify({
      "mjs": "error, email or password not found"
    })

@app.route('/create', methods=['POST'])
def create_user():
  data = request.get_json()

  user_exist = User.query.filter_by(email=data['email']).first()
  print(user_exist)

  if user_exist is not None:
    return jsonify({"response": "error, try with another email"}), 404
  else:
    create_user = User()
    create_user.name = data['name']
    create_user.email = data['email']

    pasword_hash = bcrypt.generate_password_hash(data['password'])

    create_user.password = pasword_hash

    db.session.add(create_user)
    db.session.commit()
    return jsonify({"response": "create acount", "data": data}), 201

# <valor>
@app.route('/edit_user/<int:id>', methods=['PUT'])
def edit_user(id):
  print(id)
  data = request.get_json()
  find_user = User().query.filter_by(id=id).first()

  if find_user is not None:
    find_user.name = data['name']
    find_user.email = data['email']
    find_user.password = data['password']

    print(find_user)

    db.session.commit()
    return jsonify({"message": "Edit successfully", "data": find_user.serialize()})
  else:
    return jsonify({"message": "not found"})

app.run(host="localhost" ,port=8080 , debug=True)