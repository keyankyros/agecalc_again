from flask import Flask, request, jsonify
from flask_jwt_extended import create_access_token, JWTManager
from flask_jwt_extended import jwt_required, get_jwt_identity
import pymysql
import requests
from cortex4py.api import Api
from pyhive import hive
from elasticsearch import Elasticsearch
from elasticsearch import RequestsHttpConnection


app = Flask(__name__)
app.config['SECRET_KEY']="secret"
jwt = JWTManager(app)
# Create a route to authenticate your users and return JWT Token. The
# create_access_token() function is used to actually generate the JWT.
@app.route("/login", methods=["POST"])
def create_token():
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    # Query your database for username and password
    # user = User.query.filter_by(username=username, password=password).first()
    # if user is None:
    #     # the user was not found on the database
    #     return jsonify({"msg": "Bad username or password"}), 401
    
    # create a new token with the user id inside
    if username=="test" and password=="test":
        #take cortex credentials from db
        
        access_token = create_access_token(identity=username)
        return jsonify({"access_token": access_token, "user_id": username})
        # pass
    else:
       return jsonify({"msg": "Bad username or password"}), 401 
    # access_token = create_access_token(identity=user.id)
    # return jsonify({ "token": access_token, "user_id": user.id })

@app.route("/cortex", methods=["GET"])
@jwt_required()
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    auth_header = request.headers.get("Authorization")
    if current_user == "test":

        connection = pymysql.connect(host='localhost', port=3306, user="keyan", password="keyan5630",     
                                            database="Auth")
        cursor = connection.cursor()
        get_username_for_cortex = "SELECT * FROM CortexAuth WHERE ID=1"
        cursor.execute(get_username_for_cortex)
        result = cursor.fetchone()
        print(result)
        cortex_user = result[1]
        api_key = result[3]
        connection.close()

        api = Api('http://localhost:9001', api_key)
        org = api.organizations.get_by_id('cortex')

        return jsonify(org.json())
    return jsonify({"output": "ERROR"})

@app.route("/elastic", methods=["GET"])
@jwt_required()
def elastic_func():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    auth_header = request.headers.get("Authorization")
    if current_user == "test":

        connection = pymysql.connect(host='localhost', port=3306, user="keyan", password="keyan5630",     
                                            database="Auth")
        cursor = connection.cursor()
        get_username_for_hive = "SELECT * FROM ElasticAuth WHERE ID=1"
        cursor.execute(get_username_for_hive)
        result = cursor.fetchone()
        print(result)
        es_user = result[1]
        es_pass = result[2]
        connection.close()

        client = Elasticsearch(['localhost'], port=9200, connection_class=RequestsHttpConnection, http_auth=(es_user, es_pass))
        result = client.info()

        return jsonify({"result" : str(result)})
    print(auth_header)
    return jsonify(logged_in_as=current_user), 200

@app.route("/hive", methods=["GET"])
@jwt_required()
def hive_func():
    current_user = get_jwt_identity()
    auth_header = request.headers.get("Authorization")
    if current_user = "test":
        connection = pymysql.connect(host='localhost', port=3306, user="keyan", password="keyan5630",
                                            database="Auth")
        cursor = connection.cursor()
        get_username_for_hive = "SELECT * FROM HiveAuth WHERE ID=1"
        cursor.execute(get_username_for_hive)
        result = cursor.fetchone()


if __name__ == '__main__':
    app.run(host = '0.0.0.0', port=5001, debug=True)
