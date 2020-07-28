from flask import Flask,request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash




app=Flask(__name__)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://postgres:helloworld@localhost:5000/test'
db = SQLAlchemy(app)
db.init_app(app)


class User(db.Model):
	__tablename__ = 'users'
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(80), unique=True)
	password= db.Column(db.String(120))



@app.route('/')
def index():
	return 'Hello World!'

@app.route('/login',methods=['POST'])
def login():
	# if username && username.password is correct
	# print(request.json)
	data=request.json
	username = data['username']
	password = data['password']

	if not data['username'].isalpha():
		return {'status': 203, 'msg':"Failure: only characters allowed in username"}

	if len(data['password'])<6:
		return {'status': 201, 'msg':"Failure: password should be of length 6"}

	if not any(char.isdigit() for char in data['password']) or not any(char.isalpha() for char in data['password']):
		return {'status': 202,'msg': "Failure: password to have 1 character and 1 number"}

	else:
		#check if the user actually exists
		user = User.query.filter_by(username=username).first()

		if not user or not check_password_hash(user.password, password):
			return {'status': 401, 'msg':'Unauthorized'}
		
		return {'status': 200, 'msg':'success'}


@app.route('/signup',methods=['POST'])
def signup():
	username = request.json.get('username')
	password = request.json.get('password')
	if not username.isalpha():
		return {'status': 203, 'msg':"Failure: only characters allowed in username"}

	if len(password)<6:
		return {'status': 400, 'msg':"Failure: password should be of length 6"}

	if not any(char.isdigit() for char in password) or not any(char.isalpha() for char in password):
		return {'status': 202,'msg': "Failure: password to have 1 character and 1 number"}

	# if this returns a user, then the email already exists in database
	user = User.query.filter_by(username=username).first() 

	if user: 
		return {'status': 401, 'msg':'user already exists'}

	new_user = User(username=username, password=generate_password_hash(password, method='sha256'))

	db.session.add(new_user)
	db.session.commit()

	return {'status': 200, 'msg':'success'}






		
if __name__=='__main__':
	app.run(debug=True)
	
