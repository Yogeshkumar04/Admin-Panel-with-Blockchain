from flask import Flask, flash, render_template, request,redirect, session, url_for,  jsonify, json, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from flask_bcrypt import Bcrypt
from blockchain import Block, Blockchain, time, generate_keys
from datetime import datetime



app = Flask(__name__)
blockchain = Blockchain()
app.config["SECRET_KEY"]='86a48e5e4d3d14c47fc33a97'
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///ums.sqlite"
app.config["SESSION_PERMANENT"]=False
app.config["SESSION_TYPE"]='filesystem'

db=SQLAlchemy(app)
bcrypt=Bcrypt(app)
Session(app)

# User Class
class User(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    fname=db.Column(db.String(255), nullable=False)
    lname=db.Column(db.String(255), nullable=False)
    email=db.Column(db.String(255), nullable=False)
    username=db.Column(db.String(255), nullable=False)
    edu=db.Column(db.String(255), nullable=False)
    password=db.Column(db.String(255), nullable=False)
    status=db.Column(db.Integer,default=0, nullable=False)
    balance = db.Column(db.Float, default=0.0, nullable=False)

def __repr__(self):
    return f'User("{self.id}","{self.fname}","{self.lname}","{self.email}","{self.edu}","{self.username}","{self.status}", "{self.balance}")'

# create admin Class
class Admin(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    username=db.Column(db.String(255), nullable=False)
    password=db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return f'Admin("{self.username}","{self.id}")'

    
# Main Index
@app.route('/')
def index():
    return render_template('index.html', title="")






# admin loign
@app.route('/admin/',methods=["POST","GET"])
def adminIndex():
    # chect the request is post or not
    if request.method == 'POST':
        # get the value of field
        username = request.form.get('username')
        password = request.form.get('password')
        # check the value is not empty
        if username=="" and password=="":
            flash('Please fill all the field','danger')
            return redirect('/admin/')
        else:
            # login admin by username 
            admins=Admin().query.filter_by(username=username).first()
            if admins and bcrypt.check_password_hash(admins.password,password):
                session['admin_id']=admins.id
                session['admin_name']=admins.username
                flash('Login Successfully','success')
                return redirect('/admin/dashboard')
            else:
                flash('Invalid Email and Password','danger')
                return redirect('/admin/')
    else:
        return render_template('admin/index.html',title="Admin Login")


# admin Dashboard
@app.route('/admin/dashboard')
def adminDashboard():
    if not session.get('admin_id'):
        return redirect('/admin/')
    totalUser=User.query.count()
    totalApprove=User.query.filter_by(status=1).count()
    NotTotalApprove=User.query.filter_by(status=0).count()
    return render_template('admin/dashboard.html',title="Admin Dashboard",totalUser=totalUser,totalApprove=totalApprove,NotTotalApprove=NotTotalApprove)

# Admin Set User Balance
@app.route('/admin/set-user-balance/<int:user_id>', methods=['GET', 'POST'])
def set_user_balance(user_id):
    if not session.get('admin_id'):
        # Redirect to admin login if not authenticated
        return redirect('/admin/')
    
    user = User.query.get_or_404(user_id)  # Ensures user exists or returns 404
    if request.method == 'POST':
        try:
            balance = float(request.form.get('balance', 0))  # Safely parse balance to float
            if balance >= 0:  # Example validation: balance should not be negative
                user.balance = balance
                db.session.commit()
                flash('User balance updated successfully', 'success')
            else:
                flash('Invalid balance amount', 'danger')
        except ValueError:
            # Handle case where balance is not a valid float
            flash('Invalid balance amount', 'danger')
        
        return redirect('/admin/dashboard')
    else:
        # Render balance setting page with current user's balance pre-filled or default to 0
        return render_template('admin/set_user_balance.html', user=user, current_balance=user.balance or 0)


#admin get all user 
@app.route('/admin/get-all-user', methods=["POST","GET"])
def adminGetAllUser():
    if not session.get('admin_id'):
        return redirect('/admin/')
    if request.method== "POST":
        search=request.form.get('search')
        users=User.query.filter(User.username.like('%'+search+'%')).all()
        return render_template('admin/all-user.html',title='Approve User',users=users)
    else:
        users=User.query.all()
        users_with_balance = []  # List to store user details along with balance
        for user in users:
            user_data = {
            'id': user.id,
            'fname': user.fname,
            'lname': user.lname,
            'email': user.email,
            'username': user.username,
            'edu': user.edu,
            'status': "Approved" if user.status == 1 else "Not Approved",
            'balance': user.balance  # Fetch the balance of each user
        }
        users_with_balance.append(user_data)
        
        return render_template('admin/all-user.html',title='Approve User',users=users)

# admin approve user account
@app.route('/admin/approve-user/<int:id>')
def adminApprove(id):
    if not session.get('admin_id'):
        return redirect('/admin/')
    User().query.filter_by(id=id).update(dict(status=1))
    db.session.commit()
    flash('Approve Successfully','success')
    return redirect('/admin/get-all-user')


# change admin password
@app.route('/admin/change-admin-password',methods=["POST","GET"])
def adminChangePassword():
    admin=Admin.query.get(1)
    if request.method == 'POST':
        username=request.form.get('username')
        password=request.form.get('password')
        if username == "" or password=="":
            flash('Please fill the field','danger')
            return redirect('/admin/change-admin-password')
        else:
            Admin().query.filter_by(username=username).update(dict(password=bcrypt.generate_password_hash(password,10)))
            db.session.commit()
            flash('Admin Password update successfully','success')
            return redirect('/admin/change-admin-password')
    else:
        return render_template('admin/admin-change-password.html',title='Admin Change Password',admin=admin)
    
    

# admin logout
@app.route('/admin/logout')
def adminLogout():
    if not session.get('admin_id'):
        return redirect('/admin/')
    if session.get('admin_id'):
        session['admin_id'] = None
        session['admin_name'] = None
        return redirect('/')

@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if not session.get('admin_id'):
        flash('Please login to perform this action.', 'danger')
        return redirect('/admin/')
    
    user_to_delete = User.query.get_or_404(user_id)
    db.session.delete(user_to_delete)
    db.session.commit()
    flash('User account has been successfully deleted.', 'success')
    return redirect('/admin/get-all-user')


# User Area
@app.route('/user/', methods=["POST","GET"])
def userIndex():
    if session.get('user_id'):
        return redirect('/user/dashboard')
    if request.method=="POST":
        # get the email and password from frontend
        email = request.form.get('email')
        password = request.form.get('password')
        
        # check user exist in this email or not
        users = User().query.filter_by(email=email).first()
        if users and bcrypt.check_password_hash(users.password, password):
            #check the admin approve your account or not
            # is_approve = User().query.filter_by(email==email).first()
            is_approve = User.query.filter_by(email=email).first()

            # first return the is_approve
            # return f'{is_approve.status}'

            if is_approve.status == 0:
                flash('Your Account is not approved by the Admin', 'danger')
                return redirect('/user/')
            else:
                session['user_id'] = users.id
                session['username'] = users.username
                flash('Login Successfully ', 'success')
                return redirect('/user/dashboard')
        else:
            flash('Invalid Email and Password', 'danger')
            return redirect('/user/')
    else:    
        return render_template('user/index.html', title="User Login")

# User Registration Page
@app.route('/user/signup/', methods=['POST', 'GET'])
def userRegistration():
    if session.get('user_id'):
        return redirect('/user/dashboard')
    if request.method == 'POST':
        # get all input field names
        fname = request.form.get('fname')
        lname = request.form.get('lname')
        email = request.form.get('email')
        username = request.form.get('username')
        edu = request.form.get('edu')
        password = request.form.get('password')
        
        # check all the fields are filled or not
        if fname == "" or lname == "" or email == "" or username == "" or edu == "" or password == "":
            flash('Please fill all the fields', 'danger')
            return redirect('/user/signup')
        else:
            is_email=User().query.filter_by(email=email).first()
            if is_email:
                flash('Email already Exist', 'danger')
                return redirect('/user/signup')
            else:
                hash_password = bcrypt.generate_password_hash(password, 10)
                user = User(fname=fname, lname=lname, email=email, username=username, edu=edu, password=hash_password)
                db.session.add(user)
                db.session.commit()
                flash('User Account Creation Successfully, Admin will approve your account in 10 to 30 minutes', 'success')
                return redirect('/user/')
        
    else:  
        return render_template('user/signup.html', title="User Registration")
    
# User Dashboard
@app.route('/user/dashboard')
def userDashboard():
    if not session.get('user_id'):
        return redirect('/user/')
    if session.get('user_id'):
        id=session.get('user_id')
    users=User().query.filter_by(id=id).first()
    return render_template('user/dashboard.html',title="User Dashboard",users=users)

# User Logout
@app.route('/user/logout')
def userLogout():
    if not session.get('user_id'):
        return redirect('/user/')

    if session.get('user_id'):
        session['user_id'] = None
        session['username'] = None
        return redirect('/user/')
    
# User Change Password    
@app.route('/user/change-password',methods=["POST","GET"])
def userChangePassword():
    if not session.get('user_id'):
        return redirect('/user/')
    if request.method == 'POST':
        email=request.form.get('email')
        password=request.form.get('password')
        if email == "" or password == "":
            flash('Please fill the field','danger')
            return redirect('/user/change-password')
        else:
            users=User.query.filter_by(email=email).first()
            if users:
               hash_password=bcrypt.generate_password_hash(password,10)
               User.query.filter_by(email=email).update(dict(password=hash_password))
               db.session.commit()
               flash('Password Change Successfully','success')
               return redirect('/user/change-password')
            else:
                flash('Invalid Email','danger')
                return redirect('/user/change-password')

    else:
        return render_template('user/change-password.html',title="Change Password")

# User Update Password
@app.route('/user/update-profile', methods=["POST","GET"])
def userUpdateProfile():
    if not session.get('user_id'):
        return redirect('/user/')
    if session.get('user_id'):
        id=session.get('user_id')
    users=User.query.get(id)
    if request.method == 'POST':
        # get all input field name
        fname=request.form.get('fname')
        lname=request.form.get('lname')
        email=request.form.get('email')
        username=request.form.get('username')
        edu=request.form.get('edu')
        if fname =="" or lname=="" or email=="" or username=="" or edu=="":
            flash('Please fill all the field','danger')
            return redirect('/user/update-profile')
        else:
            session['username']=None
            User.query.filter_by(id=id).update(dict(fname=fname,lname=lname,email=email,edu=edu,username=username))
            db.session.commit()
            session['username']=username
            flash('Profile update Successfully','success')
            return redirect('/user/dashboard')
    else:
        return render_template('user/update-profile.html',title="Update Profile",users=users)

# User Withdraw Funds
@app.route('/user/withdraw', methods=['GET', 'POST'])
def user_withdraw():
    # Ensure the user is logged in
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('userIndex'))

    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        withdrawal_amount = request.form.get('withdrawal_amount', type=float)
        if withdrawal_amount and 0 < withdrawal_amount <= user.balance:
            # Before updating the balance, log this transaction on the blockchain
            transaction = {
                'user_id': user.id,
                'type': 'withdraw',
                'amount': withdrawal_amount,
                'timestamp': time()
            }
            blockchain.add_new_transaction(transaction)
            blockchain.mine()  # Simulate mining to add the transaction as a new block

            # Now, update the user balance
            user.balance -= withdrawal_amount
            db.session.commit()
            flash(f'Withdrawal of {withdrawal_amount} successful.', 'success')
            return redirect(url_for('userDashboard'))
        else:
            flash('Invalid withdrawal amount.', 'danger')

    return render_template('user/withdraw.html', user=user)



@app.route('/mine', methods=['GET'])
def mine():
    last_block = blockchain.last_block()
    new_block = Block(index=last_block.index + 1,
                      transactions=blockchain.pending_transactions,
                      timestamp=time(),
                      previous_hash=last_block.hash)

    new_block.hash = new_block.compute_hash()  # Compute the hash with PoW
    added = blockchain.add_block(new_block)

    if added:
        blockchain.pending_transactions = []  # Reset the list of transactions
        return jsonify({"message": "New block mined and added to the chain", "block_index": new_block.index}), 200
    else:
        return jsonify({"message": "New block failed to be added to the chain"}), 500


@app.route('/blockchain', methods=['GET'])
def view_blockchain():
    chain_data = blockchain.to_dict()  # Get the blockchain in dict format
    print(json.dumps(chain_data, indent=4))
    for block in chain_data:
        # Check if block timestamp is an integer (Unix timestamp), then convert
        try:
            block['timestamp'] = datetime.utcfromtimestamp(int(block['timestamp'])).strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            # If it's not an integer, it's assumed to be already a correctly formatted string
            pass

        for transaction in block['transactions']:
            # Similar check for transaction timestamp
            try:
                transaction['timestamp'] = datetime.utcfromtimestamp(int(transaction['timestamp'])).strftime('%Y-%m-%d %H:%M:%S')
            except ValueError:
                # If it's not an integer, it's assumed to be already a correctly formatted string
                pass
            
                   
    return render_template('view_blockchain.html', chain_data=chain_data)


if __name__=="__main__":
    # Create Table:
    with app.app_context():
        db.create_all()
        
        # insert admin data on time | this below code only execute only one time
        # admin = Admin(username='admin', password=bcrypt.generate_password_hash('123456',10))
        # db.session.add(admin)
        # db.session.commit()
         
        
    app.run(debug=True)
