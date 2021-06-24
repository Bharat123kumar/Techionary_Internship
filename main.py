from Crypto.Cipher import PKCS1_OAEP as pk
from Crypto.PublicKey import RSA
import cx_Oracle as cx
import schedule, time

def checkTableExists(dbcon, dbcur):
    try:
        dbcur.execute("SELECT * FROM passwordM")
        return True
    except cx.DatabaseError as e:
        x = e.args[0]
        if x.code == 942: ## Only catch ORA-00942: table or view does not exist error
            return False
        else:
            raise e
def OutputTypeHandler(cursor, name, defaultType, size, precision, scale):
    if defaultType == cx.DB_TYPE_CLOB:
        return cursor.var(cx.DB_TYPE_LONG, arraysize=cursor.arraysize)
    if defaultType == cx.DB_TYPE_BLOB:
        return cursor.var(cx.DB_TYPE_LONG_RAW, arraysize=cursor.arraysize)

conn= cx.connect('SYSTEM/1234@localhost/GBLDB')
cur=conn.cursor()
conn.outputtypehandler = OutputTypeHandler

if not checkTableExists(conn,cur):
    cur.execute("create table passwordM(App varchar2(50) not null, username varchar2(50) not null, password blob not null)")
    cur.execute("commit")

private_key= RSA.generate(2048)
public_key= private_key.publickey()

def generateKey():
    global private_key
    global public_key
    private_key= RSA.generate(2048)
    public_key= private_key.publickey()

def RSAEncryption(data):
    global public_key
    cipher= pk.new(key=public_key)
    ciphertext= cipher.encrypt(data.encode('utf-8'))
    return ciphertext


def RSADecryption(ct):
    global private_key
    decipher= pk.new(key=private_key)
    data=decipher.decrypt(ct)
    return data.decode('utf-8')


def askDetails():
    app= input("ENTER THE NAME OF APP: ")            
    username= input("ENTER YOUR USERNAME: ")
    password= input('ENTER YOUR PASSWORD: ')
    return app, username, password
    
        

def change():
    pswds=[]
    rowids=[]
    cur.execute("select rowid, password from passwordM")
    for x in cur:
        pswds.append(RSADecryption(x[1]))
        rowids.append(x[0])
    generateKey()
    for i in range(len(rowids)):
        ciphertext=RSAEncryption(pswds[i])
        cur.execute("update passwordM set password= :vp where rowid= :vr", vp=ciphertext, vr= rowids[i])
        cur.execute("commit")
        
flag=0
while(1):
    print("\n\nMAIN MENU\n1. Retrieve Password 2. Enter new password")
    ch=input("enter your choice: ")
    if(ch=='1'):
        flag+=1
        app=input("\nenter the name of the app: ")
        username=input("\nEnter the username: ")
        cur.execute("select password from passwordM where app=:va and username=:vu", va=app, vu=username)
        if cur.fetchone()==None:
            print("\nNo entry exists with app: '{}' and username: '{}'\nCheck again and enter correct details!!".format(app,username))
            continue
        cur.execute("select password from passwordM where app=:va and username=:vu", va=app, vu=username)
        for x in cur:
            ciphertext=x[0]
        print(RSADecryption(ciphertext))
    elif(ch=='2'):
        flag+=1
        app, username, password=askDetails()
        ciphertext= RSAEncryption(password)
        try:
            cur.execute("insert into passwordM (app, username, password) values(:v1, :v2, :v3)", v1=app, v2=username, v3=ciphertext)
            cur.execute("commit")
        except cx.DatabaseError as e:
            x = e.args[0]
            if x.code == 1400: 
                print("\nApp and/or Username cannot be empty")
            else:
                raise e
    else:
        print("\nPlease select appropriate choice")

    if(flag>=3):
        flag=0
        change()

    
