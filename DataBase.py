# # importing hashlib
import hashlib
# # Import SQL lite
import sqlite3 as sq
import threading

# Implementing the DataBase


class Sql:
    def __init__(self):
        self.connect = sq.connect('/main.db')
        self.cursor = self.connect.cursor()

    def insert(self, user, email, password):
        try:
            self.cursor.execute('CREATE TABLE User(Name TEXT, Email TEXT, Pass TEXT)')
            self.cursor.execute('INSERT INTO User VALUES(?,?,?)', (user, email, pas_hash(password)))
            self.connect.commit()

        except:
            self.cursor.execute('INSERT INTO User VALUES(?,?,?)', (user, email, pas_hash(password)))
            self.connect.commit()
        return

    def checked(self, user, email, password):
        check = self.cursor.execute('SELECT Pass FROM User WHERE Name == ? AND Email == ?', (user, email))
        self.connect.commit()
        try:
            pas = list(*check)[0]
        except:
            return False

        if pas_hash(password) == pas:
            return True
        else:
            return False

    def output(self):
        data = self.cursor.execute('SELECT * FROM User')
        for x in data:
            print(x)

    def quit(self):
        self.connect.close()

# First of all we use sha512 hashing algorithm for hashing the password


def pas_hash(password: str):
    hash = hashlib.sha512(password.encode('UTF-8')).hexdigest()
    return hash


ob = Sql()
