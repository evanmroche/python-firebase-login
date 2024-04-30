from firebase_admin import credentials
from firebase_admin import db
import firebase_admin
import json
import bcrypt

# Load the service account key JSON file.
with open("service-account-key.json") as f:
    cred_json = json.load(f)

cred = credentials.Certificate(cred_json)

# Initialize the app with a service account, granting admin privileges
firebase_admin.initialize_app(cred, {
    'databaseURL': cred_json["databaseURL"]
})

ref = db.reference('/')

def getUsers():
    ref = db.reference('/')
    return ref.get()

def hashPassword(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()) 

def checkHashedPass(password, pass_hash):
    return bcrypt.checkpw(password.encode('utf-8'), pass_hash.encode('utf-8'))

def addUserPassCombo(username, password):
    users_dict = getUsers()
    pass_hash = hashPassword(password)
    users_dict['users'][username] = pass_hash
    ref.set(users_dict)

def checkUserPassCombo(username, password):
    users_dict = getUsers()
    try: 
        pass_hash = users_dict['users'][username]
        if checkHashedPass(password, pass_hash):
            print("Success: Valid user/pass combo!")
        else:
            print("Error: Invalid user/pass combo!")
    except Exception as e:
        print(e)
        print("Error: Username not found!")

def login():
    username = input("Username: ")
    password = input("Password: ")
    checkUserPassCombo(username, password)

def createUser():
    username = input("Username: ")
    password = input("Password: ")
    addUserPassCombo(username, password)

def printMenu():
    choice = input("Would you like to create an account or log in?\nEnter a letter [c,l]: ")
    if choice == "c":
        createUser()
    elif choice == "l":
        login()
    else:
        print("Invalid choice!")
    
printMenu()