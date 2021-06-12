import yaml
from flask import Flask, request, jsonify, session
from flask_cors import cross_origin
from flask_jwt_extended import get_jwt_identity, jwt_required, JWTManager, create_access_token
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
mysql = MySQL(app)

db = yaml.load(open('db.yaml'), Loader=yaml.FullLoader)
app.config['MYSQL_HOST'] = db['DB_HOST']
app.config['MYSQL_USER'] = db['DB_USER']
app.config['MYSQL_PASSWORD'] = db['DB_PASSWORD']
app.config['MYSQL_DB'] = db['DB_NAME']
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET")
jwt = JWTManager(app)


@app.route('/register', methods=['POST'])
@cross_origin()
def register():
    if request.method == 'POST':
        user_data = request.get_json(force=True)
        first_name = user_data['first_name']
        last_name = user_data['last_name']
        user_email = user_data['email']
        user_name = user_data['user_name']
        password = generate_password_hash(user_data['password'], 'sha256', 20)
        cursor = mysql.connection.cursor()
        json_response = {
            "post_status": False,
            "user_name_duplicate": False,
            "user_email_duplicate": False,
            "form_check": {
                "first_name": {
                    "error_blank": True
                },
                "last_name": {
                    "error_blank": True
                },
                "user_email": {
                    "error_blank": True
                },
                "user_name": {
                    "error_blank": True, "error_min_length_5": True
                },
                "password": {
                    "error_blank": True, "error_min_length_8": True
                },
            }
        }
        form_error = False
        if user_data['first_name']:
            json_response['form_check']['first_name']["error_blank"] = False
        if user_data['last_name']:
            json_response['form_check']['last_name']["error_blank"] = False
        if user_data['email']:
            json_response['form_check']['user_email']["error_blank"] = False
        if user_data['user_name']:
            json_response['form_check']['user_name']["error_blank"] = False
        if len(user_data['user_name']) > 4:
            json_response['form_check']['user_name']["error_min_length_5"] = False
        if user_data['password']:
            json_response['form_check']['password']["error_blank"] = False
        if len(user_data['password']) > 7:
            json_response['form_check']['password']["error_min_length_8"] = False
        duplicate_user_req = cursor.execute("SELECT * FROM user WHERE user_name = %s", ([user_name]))
        if duplicate_user_req > 0:
            json_response['user_name_duplicate'] = True
        duplicate_email_req = cursor.execute("SELECT * FROM user WHERE email = %s", ([user_email]))
        if duplicate_email_req > 0:
            json_response['user_email_duplicate'] = True
        if json_response["user_name_duplicate"] is False and json_response["user_email_duplicate"] is False:
            for p_item in json_response['form_check']:
                parent_items = json_response['form_check'][p_item]
                for c_item in parent_items:
                    if parent_items[c_item]:
                        form_error = True
                        print('Form data error empty values or wrong length')
                    else:
                        form_error = False
            if not form_error:
                cursor.execute(
                    "INSERT INTO user(first_name, last_name, user_name, email, password) VALUES ( %s, %s, %s, %s, %s)",
                    ([first_name, last_name, user_name, user_email, password]))
                json_response["post_status"] = True
                mysql.connection.commit()
                cursor.close()
        return json_response
    else:
        return 'Method Not Allowed', 405


@app.route('/login', methods=['POST'])
@cross_origin()
def login():
    cursor = mysql.connection.cursor()
    response = {
        "first_name": '',
        "loggedIn": '',
        "last_name": ''
    }
    if request.method == 'POST':
        data = request.get_json(force=True)
        user_name = data['user_name']
        user_password = data['user_password']
        result_value = cursor.execute("SELECT * FROM user WHERE user_name = %s", ([user_name]))
        if result_value > 0:
            print(data)
            user = cursor.fetchone()
            print(check_password_hash(user['password'], user_password))

            if check_password_hash(user['password'], user_password):
                print('checked')
                access_token = create_access_token(identity=user_name)
                response = {
                    "loggedIn": True,
                    "first_name": user['first_name'],
                    "last_name": user['last_name'],
                    "token": access_token
                }
                return jsonify(response)
            else:
                response['loggedIn'] = False
                return jsonify(response)
        else:
            cursor.close()
            return jsonify(resource, loggedIn=False)
    if request.method == 'GET':
        current_user = get_jwt_identity()
        return jsonify(logged_in_as=current_user)


@app.route('/token', methods=['GET'])
@cross_origin()
@jwt_required()
def token():
    user = get_jwt_identity()
    if request.method == 'GET' and user:
        cursor = mysql.connection.cursor()
        result_value = cursor.execute("SELECT * FROM user WHERE user_name = %s", ([user]))
        if result_value > 0:
            user_data = cursor.fetchone()
            return jsonify(user_data)
        else:
            return 'User data not found', 404
    else:
        return 'Method Not Allowed', 405


@app.route('/logout', methods=['GET'])
@cross_origin()
def logout():
    if request.method == 'GET':
        session.clear()
        return {
            "loggedIn": False,
        }
    else:
        return 'logout error', 405


if __name__ == '__main__':
    app.run(debug=True)
