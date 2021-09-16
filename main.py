import glob
glob.setglob()
from custom_func import *
from flask import Flask, jsonify, request, render_template, redirect, url_for, make_response
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

app = Flask(_name_)
app.config['SECRET_KEY']=os.getenv("PASS_KEY")

client=MongoClient(glob.conn_str,tlsCAFile=certifi.where())
#Domain Name in explore functions

def token_required(f):
   @wraps(f)
   def decorator(*args, **kwargs):
       token=None
       if 'x-access-tokens' in request.cookies:
           token=request.cookies['x-access-tokens']
       if not token:
            return render_template('login.html',error="Token not provided, login to get your token.")
            #return jsonify({"Message":"Token not provided."})
       try:
            data=jwt.decode(token,app.config['SECRET_KEY'])
       except:
           return render_template('login.html',error="Token is invalid, login to get your token.")

       return f(*args, **kwargs)
   return decorator

@app.route('/login',methods=["POST", "GET"])
def login():
    if request.method=="GET":
        return render_template('login.html')
    password=request.form['password']
    db=client.db
    to_check=db.first
    for all_p in to_check.find():
        stored_password=all_p['password']
    chck=verify_password(stored_password,password)
    if chck==False:
        return render_template('login.html',error="Incorrect password provided.")
    all_chars=string.ascii_letters+string.digits
    random_string=''.join(random.choices(all_chars, k=20))
    token = jwt.encode({'random': random_string, 'exp' : datetime.utcnow() + timedelta(minutes=300)}, app.config['SECRET_KEY'])
    resp=make_response(render_template('credentials.html'))
    resp.set_cookie('x-access-tokens',token)
    return resp

#Change Password
@app.route('/change_password',methods=["POST"])
@token_required
def change_password():
    old_password=request.form['old_password']
    new_password=request.form['new_password']
    cnf_new_password=request.form['cnf_new_password']
    if new_password != cnf_new_password:
        return render_template('.html',error="Passwords do not match.")
    db=client.db
    to_check=db.first
    for all_p in to_check.find():
        stored_password=all_p['password']
    chck=verify_password(stored_password,old_password)
    if chck==False:
        return render_template('changepassword.html',error="Incorrect old password.")
    hash_password(new_password)
    return redirect(url_for('logout'))

@app.route('/logout',methods=['GET'])
@token_required
def logout():
    resp = make_response(redirect(url_for('login')))
    resp.delete_cookie('x-access-tokens')
    return resp

def apprun():
    cwd=os.getcwd()
    app.run(debug=True, host='0.0.0.0', port=5000 , ssl_context=(cwd+'\\cert.pem', cwd+'\\key.pem'), use_reloader=False)

if _name_ == '_main_':
    cwd=os.getcwd()
    #test()
    pr=subprocess.Popen("powershell Get-NetFirewallRule -DisplayName \"AssetMonitoring\"",stdout=subprocess.PIPE)
    pr.communicate()[0]
    
    if(pr.returncode==1):
        input("The tool requires port 5000 to be open inside the domain network.A Prompt would ask for adminsitrator privileges to create a rule in firewall for the port.\nPress Enter to continue...")
        print("Creating the rule in firewall")
        subprocess.Popen("powershell -noprofile -command \"&{Start-Process powershell -Verb Runas -ArgumentList '-noprofile -executionpolicy bypass -file "+cwd+"\\create_rule.ps1'}\"",shell=True)    
    
    t=threading.Thread(target=apprun, daemon=True).start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Exiting")
        exit(0)
