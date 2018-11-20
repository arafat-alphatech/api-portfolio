from flask import Flask
from flask_cors import CORS
from flask_restful import Resource, Api, reqparse, marshal, fields

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc, insert, ForeignKey, DateTime, distinct, func
from sqlalchemy.orm import relationship
from flask_migrate import Migrate, MigrateCommand
from flask_script import Manager
from flask_jwt_extended import JWTManager, create_access_token, verify_jwt_in_request, get_jwt_claims, jwt_required, get_jwt_identity, get_raw_jwt
from functools import wraps
import sys, json, datetime, math

app = Flask(__name__)
CORS(app, resources={r"*": { "origins" : "*" } } )
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://marafat:admin1234@dbapi.cg5tsukjjtaf.ap-southeast-1.rds.amazonaws.com/portofolio'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:1234567890@localhost/portfolio'
app.config['CORS_HEADERS'] = 'Content-Type'
app.config['JWT_SECRET_KEY'] = 'ini-secret-banget'

db = SQLAlchemy(app)
migrate = Migrate(app, db)
manager = Manager(app)
manager.add_command('db', MigrateCommand)
jwt = JWTManager(app)

api = Api(app)

# Check if claims in token is admin, IT'S THE ADMIN !!!
def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        claims = get_jwt_claims()
        if claims['type'] != 'admin':
            # You are not ADMIN
            return {'message':'FORBIDDEN'}, 403, {'Content-Type': 'application/json'}
        else:
            # WELCOME ADMIN
            return fn(*args, **kwargs)
    return wrapper

# Check if claims in token is pelapak,
def pelapak_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        claims = get_jwt_claims()
        if claims['type'] != 'pelapak':
            # You are not pelapak, maybe you are the ADMIN, or just guest
            return {'message':'FORBIDDEN'}, 403, {'Content-Type': 'application/json'}
        else:
            # WELCOME PELAPAK
            return fn(*args, **kwargs)
    return wrapper

######################################################
##################   M  O  D  E  L  ##################
######################################################

class Users(db.Model):
    id = db.Column(db.Integer, primary_key= True)
    name = db.Column(db.String(255), nullable= False)
    username = db.Column(db.String(255), nullable= False)
    email = db.Column(db.String(255), unique= True, nullable= False)
    password = db.Column(db.String(255), nullable= False)
    no_telp = db.Column(db.String(255))
    alamat = db.Column(db.String(255))
    type = db.Column(db.String(30), nullable = False)
    createdAt = db.Column(db.DateTime, default= db.func.current_timestamp())
    updatedAt = db.Column(db.DateTime, default= db.func.current_timestamp())
    buku =  db.relationship('Buku', backref='users')
    cart =  db.relationship('Cart', backref='users')

    def __repr__(self):
        return '<Users %r>' % self.id

# Model Buku: save books data, FK with author data
class Buku(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    judul = db.Column(db.String(255), nullable= False)
    isbn = db.Column(db.String(255), unique= True, nullable= False)
    penerbit = db.Column(db.String(255))
    author = db.Column(db.String(255), nullable= False)
    harga = db.Column(db.Integer, nullable = False)
    status= db.Column(db.String(30), nullable= False)
    stok = db.Column(db.Integer)
    url_picture= db.Column(db.String(255))
    createdAt = db.Column(db.DateTime, default= db.func.current_timestamp())
    updatedAt = db.Column(db.DateTime, default= db.func.current_timestamp())
    #FK
    pelapak_id= db.Column(db.Integer, db.ForeignKey("users.id"), nullable= False)
    kategori = db.Column(db.Integer, db.ForeignKey("kategori.id"), nullable= False)
    detailcart = db.relationship("DetailCart", backref='buku')


    def __repr__(self):
        return '<Buku %r>' % self.id

class Kategori(db.Model):
    id = db.Column(db.Integer, primary_key= True)
    kategori = db.Column(db.String(255), nullable = False)
    createdAt = db.Column(db.DateTime, default= db.func.current_timestamp())
    updatedAt = db.Column(db.DateTime, default= db.func.current_timestamp())
    buku = db.relationship("Buku", backref='kategori_buku')

    def __repr__(self):
        return '<Kategori %r>' % self.id

class Cart(db.Model):
    id = db.Column(db.Integer, primary_key= True)
    id_user = db.Column(db.Integer, db.ForeignKey('users.id'), nullable= False)
    total_qty = db.Column(db.Integer, default= 0)
    total_price = db.Column(db.Integer, default= 0)
    status = db.Column(db.Boolean, default= False)
    createdAt = db.Column(db.DateTime, default= db.func.current_timestamp())
    updatedAt = db.Column(db.DateTime, default= db.func.current_timestamp())
    detailcart = db.relationship("DetailCart", backref='cart')

    def __repr__(self):
        return '<Cart %r>' % self.id

class DetailCart(db.Model):
    id = db.Column(db.Integer, primary_key= True)
    id_cart = db.Column(db.Integer, db.ForeignKey('cart.id'), nullable= False)
    id_buku = db.Column(db.Integer, db.ForeignKey('buku.id'), nullable= False)
    qty = db.Column(db.Integer, nullable= False)
    price = db.Column(db.Integer, nullable= False)
    status = db.Column(db.Boolean, default= True)
    createdAt = db.Column(db.DateTime, default= db.func.current_timestamp())
    updatedAt = db.Column(db.DateTime, default= db.func.current_timestamp())

    def __repr__(self):
        return '<DetailCart %r>' % self.id

###############################################################
################## E N D      M  O  D  E  L  ##################
###############################################################

# Resource to get the JWT token 
class LoginResource(Resource):
    # auth, just user with author token can access this method 
    @pelapak_required
    def get(self):
        # get user identity from token by claims 
        current_user = get_jwt_identity()

        # find data user by user identity (id users from token by claims)
        qty= Users.query.get(current_user)
        data = {
            "name": qty.name,
            "username": qty.username,
            "email": qty.email,
            "password": qty.password,
            "no_telp": qty.no_telp,
            "alamat": qty.alamat
        }
        return data, 200

    # method to get jwt token for author already have account
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', location= 'json', required= True)
        parser.add_argument('password', location= 'json', required= True)

        args = parser.parse_args()

        # get data users by username and password
        qry = Users.query.filter_by( username= args['username'], password= args['password']).first()
        
        # check is user with username and password have account ?
        if qry == None:
            # if not return 401
            return {"message": "UNAUTHORIZED"}, 401
        
        # if have account create token for him
        token = create_access_token(identity= qry.id, expires_delta = datetime.timedelta(days=1))

        # then return to him
        return {"token": token, "id_user": qry.id, "type": qry.type, "name": qry.name}, 200

# Resource to register your account
class RegisterResource(Resource):
    def post(self, act = None):
        # collect data from body 
        parser = reqparse.RequestParser()
        parser.add_argument('name', type= str, location='json', required= True, help= 'name must be string and exist')
        parser.add_argument('username', type= str, location='json', required= True, help= 'username must be string and exist')
        parser.add_argument('email', type= str, location='json', required= True, help= 'email must be string and exist')
        parser.add_argument('password', type= str, location='json', required=True, help= 'password must be string and exist')
        parser.add_argument('alamat', type= str, location='json', required=True, help= 'alamat must be string and exist')
        parser.add_argument('no_telp', type= str, location='json', required=True, help= 'no_telp must be string and exist')
        parser.add_argument('secret', type= str, location='json', required=False, help= 'secret must be string')

        # parse it in args variable
        args = parser.parse_args()

        if(act != None):
            if act == 'username':
                qry = Users.query.filter_by(username= args['username']).first()
                if qry == None:
                    msg = "SUCCESS" + args['username']
                    return {"message": msg }, 200
                return {"message": "ERROR"}, 406

            if act == 'email':
                qry = Users.query.filter_by(email= args['email']).first()
                if qry == None:
                    return {"message": "SUCCESS"}, 200
                return {"message": "ERROR"}, 406
        
        mySecret = "ADMIN"

        # # find user data by username
        # qry= Users.query.filter_by(username= args['username']).first()
        # # if username already taken
        # if qry != None:
        #     # tell him that the username already taken
        #     return {"message": "Username telah digunakan"}, 406

        # # or check it by email
        # qry= Users.query.filter_by(email= args['email']).first()
        # if qry != None:
        #     # if email have taken, tell him
        #     return {"message": "Email telah digunakan"}, 406

        # if username and email available then check its admin or pelapak
        if(args["secret"] != None and args["secret"] == mySecret):
            auth = 'admin'
        else:
            auth = 'pelapak'

        data = Users(
                name= args['name'], 
                username= args['username'], 
                email= args['email'], 
                password= args['password'], 
                alamat= args['alamat'], 
                no_telp= args['no_telp'], 
                type= auth
            )

        db.session.add(data)
        # insert it to BD 
        db.session.commit()

        # and create token for him
        token = create_access_token(identity= data.id, expires_delta = datetime.timedelta(days=1))
        # then give it to him
        return {"message": "SUCCESS" , "token": token, "id_user": data.id, "type": auth, "name": data.name}, 200

# create claims to user token
@jwt.user_claims_loader
def add_claim_to_access_token_uhuyy(identity):
    # find users data by identity field in token
    data = Users.query.get(identity)
    # add 'type' as key and type from db as value 
    return { "type": data.type }

class AuthorResource(Resource):
    # field yang ingin di tampilkan lewat marshal
    buku_field= {
        "id": fields.Integer,
        "judul": fields.String, 
        "isbn": fields.String,
        "author": fields.String,
        "penerbit": fields.String,
        "kategori_buku.kategori": fields.String,
        "harga": fields.Integer,
        "stok": fields.Integer,
        "url_picture": fields.String,
        "status": fields.String,
        "createdAt": fields.String,
        "updatedAt": fields.String,
        "users.name": fields.String
    }
    
    @pelapak_required
    def get(self, id= None):
        # get identity from user token
        current_user = get_jwt_identity()

        ans = {}
        ans["message"] = "SUCCESS"
        rows = []

        # if method get have id params
        if(id != None):
            # get data where id from params
            qry = Buku.query.filter_by(pelapak_id = current_user, id = id).first()
            # if not found data
            if(qry == None):
                # return message
                return {'message': 'Data not found !!!'}, 404
            # if found data
            rows = marshal(qry, self.buku_field)
            ans["data"] = rows
            # return data
            return ans, 200

        # if id params stil None (nothing data from id params), get all data on pelapak id 
        qry = Buku.query.filter_by(pelapak_id = current_user)
        
        for row in qry.all():
            # collect all data to rows
            rows.append(marshal(row, self.buku_field))
        
        ans["data"] = rows

        # return all data
        return ans, 200

    @pelapak_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("judul", type= str, help= 'judul key must be an string and exist', location= 'json', required= True)
        parser.add_argument("isbn", type= str, help= 'isbn id must be an string and exist', location= 'json', required= True)
        parser.add_argument("author", type= str, help= 'author must be an string and exist', location= 'json', required= True)
        parser.add_argument("penerbit", type= str, help= 'penerbit must be an string and exist', location= 'json', required= True)
        parser.add_argument("kategori", type= int, help= 'kategori must be an integer and exist', location= 'json', required= False)
        parser.add_argument("harga", type= int, help= 'harga must be an integer and exist', location= 'json', required= True)
        parser.add_argument("stok", type= int, help= 'stok must be an integer and exist', location= 'json', required= True)
        parser.add_argument("url_picture", type= str, help= 'url picture must be an string and exist', location= 'json', required= False, default= 'default pict')
        parser.add_argument("status", type= str, help= 'status must be an string', location= 'json', required= False, default= 'show')

        args = parser.parse_args()

        # get identity from token
        current_user = get_jwt_identity()
        # get data on isbn
        qry = Buku.query.filter_by(isbn = args["isbn"], pelapak_id = current_user).first()
        # if have data with same isbn number
        if(qry != None):
            # return that isbn cannot duplicate
            return {"message": "isbn cannot duplicate"}, 406

        # insert all data
        data = Buku(
                judul= args["judul"],
                isbn= args["isbn"],
                author= args["author"],
                penerbit= args["penerbit"],
                kategori= args["kategori"],
                harga= args["harga"],
                stok= args["stok"],
                url_picture= args["url_picture"],
                status= args["status"],
                pelapak_id= current_user
            )
        db.session.add(data)
        db.session.commit()

        return {"message": "SUCCESS"}, 200

    @pelapak_required
    def patch(self, id):
        # get identity from token
        current_user = get_jwt_identity()
        # get data where on id
        data = Buku.query.filter_by(pelapak_id = current_user, id = id).first()

        # if not have data
        if(data == None): 
            # return not found
            return {'message': 'Data not found !!!'}, 404

        parser = reqparse.RequestParser()
        parser.add_argument("judul", type= str, help= 'judul key must be an string and exist', location= 'json', required= False)
        parser.add_argument("isbn", type= str, help= 'isbn id must be an string and exist', location= 'json', required= False)
        parser.add_argument("author", type= str, help= 'author must be an string and exist', location= 'json', required= False)
        parser.add_argument("penerbit", type= str, help= 'penerbit must be an string and exist', location= 'json', required= False)
        parser.add_argument("kategori", type= str, help= 'kategori must be an string and exist', location= 'json', required= False)
        parser.add_argument("harga", type= int, help= 'harga must be an integer and exist', location= 'json', required= False)
        parser.add_argument("stok", type= int, help= 'stok must be an integer and exist', location= 'json', required= False)
        parser.add_argument("url_picture", type= str, help= 'url picture must be an string and exist', location= 'json', required= False)
        parser.add_argument("status", type= str, help= 'status must be an string', location= 'json', required= False)

        args = parser.parse_args()

        # update the data
        if args["judul"] != None:
            data.judul= args["judul"]
        if args["isbn"] != None:
            data.isbn= args["isbn"]
        if args["author"] != None:
            data.author= args["author"]
        if args["penerbit"] != None:
            data.penerbit= args["penerbit"]
        if args["kategori"] != None:
            data.kategori= args["kategori"]
        if args["harga"] != None:
            data.harga= args["harga"]
        if args["stok"] != None:
            data.stok= args["stok"]
        if args["url_picture"] != None:
            data.url_picture= args["url_picture"]
        if args["status"] != None:
            data.status= args["status"]

        # update updatedAt field when update data
        data.updatedAt = db.func.current_timestamp()
        
        db.session.add(data)
        db.session.commit()

        return {"message": "SUCCESS"}, 200

    @pelapak_required
    def delete(self, id):
        # get identity from token
        current_user = get_jwt_identity()
        # get data
        data = Buku.query.filter_by(pelapak_id = current_user, id = id).first()

        #check if data exist
        if data == None:
            # return not found it nothing data
            return {'message': "Data not found!"}, 404

        db.session.delete(data)
        db.session.commit()
        return {'message': "SUCCESS"}, 200

class PublicResource(Resource):
    # field yang ingin di tampilkan lewat marshal
    buku_field= {
        "id": fields.Integer,
        "judul": fields.String, 
        "isbn": fields.String,
        "author": fields.String,
        "penerbit": fields.String,
        "kategori_buku.kategori": fields.String,
        "kategori": fields.String,
        "harga": fields.Integer,
        "stok": fields.Integer,
        "url_picture": fields.String,
        "status": fields.String,
        "createdAt": fields.String,
        "updatedAt": fields.String,
        "users.name": fields.String,
        "users.id": fields.Integer
    }
    
    def get(self, id = None):

        # if method get have id params
        if(id != None):
            # get data where id from params
            qry = Buku.query.get(id)
            # if not found data
            if(qry == None):
                # return message
                return {'message': 'Data not found !!!'}, 404
            # if found data
            ans = {
                "page": 1,
                "total_page": 1,
                "per_page": 25,
                "data": []
            }

            rows = marshal(qry, self.buku_field)
            ans["data"] = rows
            # return data
            return ans, 200

        parser = reqparse.RequestParser()
        parser.add_argument("p", type= int, location= 'args', default= 1)
        parser.add_argument("rp", type= int, location= 'args', default= 25)
        #filter,  query where
        parser.add_argument("id",type= int, help= 'id must be an integer', location= 'args')
        parser.add_argument("judul",type= str, help= 'judul must be an string', location= 'args')
        parser.add_argument("isbn",type= int, help= 'isbn must be an integer', location= 'args')
        parser.add_argument("author",type= str, help= 'author must be an string', location= 'args')
        parser.add_argument("penerbit",type= str, help= 'penerbit must be an string', location= 'args')
        parser.add_argument("harga",type= int, help= 'harga must be an integer', location= 'args')
        parser.add_argument("stok",type= int, help= 'stok must be an integer', location= 'args')
        parser.add_argument("kategori",type= str, help= 'kategori must be an integer', location= 'args')
        parser.add_argument("is_login",type= bool, help= 'is_login must be bool', location= 'args')
        parser.add_argument("id_user",type= int, help= 'id_user must be integer', location= 'args')
        #order, query order by
        parser.add_argument("orderBy", help= 'invalid orderBy', location= 'args', choices=('id','isbn', 'judul', 'status', 'harga', 'stok', 'penerbit', 'kategori', 'createdAt', 'updatedAt'))
        parser.add_argument("sort", help= 'invalid sort value', location= 'args', choices=('asc', 'desc'), default = 'asc')

        args = parser.parse_args()

        qry = Buku.query

        if args['p'] == 1:
            offset = 0
        else:
            offset = (args['p'] * args['rp']) - args['rp']

        # if user login
        if args['is_login'] == True:
            if args['id_user'] != None:
                qry = qry.filter(Buku.pelapak_id != args['id_user'])


        # query WHERE
        if args['id'] != None:
            qry = qry.filter(Buku.id.like("%"+args['id']+"%"))
        if args["judul"] != None:
            qry = qry.filter(Buku.judul.like("%"+args["judul"]+"%")) 
        if args["isbn"] != None:
            qry = qry.filter(Buku.isbn.like("%"+args["isbn"]+"%")) 
        if args["author"] != None:
            qry = qry.filter(Buku.author.like("%"+args["author"]+"%")) 
        if args["penerbit"] != None:
            qry = qry.filter(Buku.penerbit.like("%"+args["penerbit"]+"%")) 
        if args["kategori"] != None:
            if args["kategori"] != 'semua':
                qry = qry.filter_by(kategori = args["kategori"]) 
        if args["harga"] != None:
            qry = qry.filter(Buku.harga.like("%"+args["harga"]+"%")) 
        if args["stok"] != None:
            qry = qry.filter(Buku.stok.like("%"+args["stok"]+"%")) 
           
        qry = qry.filter_by(status = "show")
        # query ORDER BY
        if args['orderBy'] != None:

            if args["orderBy"] == "id":
                field_sort = Buku.id
            elif args["orderBy"] == "isbn":
                field_sort = Buku.isbn
            elif args["orderBy"] == "judul":
                field_sort = Buku.judul
            elif args["orderBy"] == "status":
                field_sort = Buku.status
            elif args["orderBy"] == "harga":
                field_sort = Buku.harga
            elif args["orderBy"] == "stok":
                field_sort = Buku.stok
            elif args["orderBy"] == "penerbit":
                field_sort = Buku.penerbit
            elif args["orderBy"] == "kategori":
                field_sort = Buku.kategori
            elif args["orderBy"] == "createdAt":
                field_sort = Buku.createdAt
            elif args["orderBy"] == "updatedAt":
                field_sort = Buku.updatedAt

            if args['sort'] == 'desc':
                qry = qry.order_by(desc(field_sort))
               
            else:
                qry = qry.order_by(field_sort)

        # query LIMIT, pagination
        
        rows= qry.count()
        qry =  qry.limit(args['rp']).offset(offset)
        tp = math.ceil(rows / args['rp'])
        
        ans = {
            "page": args['p'],
            "total_page": tp,
            "per_page": args['rp'],
            "data": []
        }

        rows = []
        for row in qry.all():
            rows.append(marshal(row, self.buku_field))

        ans["data"] = rows

        return ans, 200

class KategoriResource(Resource):
    kategori_field = {
        "id": fields.Integer,
        "kategori" : fields.String,
        "createdAt" : fields.String,
        "updatedAt" : fields.String
    }

    def get(self):
        data = Kategori.query.order_by('kategori')
        ans = {
            "message": "SUCCESS",
            "data": []
        }

        rows = []
        for row in data.all():
            rows.append(marshal(row, self.kategori_field))
        ans["data"] = rows
        return ans, 200
        
    @admin_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("kategori", type= str, help= 'judul key must be an string and exist', location= 'json', required= True)
        
        args = parser.parse_args()

        data = Kategori.query.filter_by(kategori = args["kategori"]).first()
        if (data != None):
            return {"message": "Cannot duplicate kategori"}, 406

        data = Kategori(
                kategori= args["kategori"],
            )
        db.session.add(data)
        db.session.commit()

        return {"message": "SUCCESS"}, 200
    
    @admin_required
    def patch(self, id):
        data = Kategori.query.get(id)

        if(data == None):
            return {"message": "Data Not Found!"}, 404

        parser = reqparse.RequestParser()
        parser.add_argument("kategori", type= str, help= 'judul key must be an string and exist', location= 'json', required= True)
        
        args = parser.parse_args()
        data.kategori = args['kategori']
        db.session.add(data)
        db.session.commit()

        return {"message": "SUCCESS"}, 200

    @admin_required
    def delete(self, id):
        data = Kategori.query.get(id)

        #check if data exist
        if data == None:
            # return not found it nothing data
            return {'message': "Data not found!"}, 404

        db.session.delete(data)
        db.session.commit()
        return {'message': "SUCCESS"}, 200

class CartResource(Resource):
    cart_detail_field= {
        "id": fields.Integer,
        "buku.id": fields.Integer,
        "buku.judul": fields.String,
        "buku.users.name": fields.String,
        "qty": fields.Integer,
        "price": fields.Integer,
    }

    cart_field = {
        "id": fields.Integer,
        "total_qty": fields.Integer,
        "total_price": fields.Integer,
        "updatedAt": fields.String
    }

    @pelapak_required
    def get(self):
        current_user = get_jwt_identity()

        parser = reqparse.RequestParser()
        parser.add_argument("status", type= bool, help= 'judul key must be an string and exist', location= 'args', default= False)
        args = parser.parse_args()
        
        cart = Cart.query

        if args['status'] == False:
            cart = cart.filter_by(id_user = current_user, status = False).first()
            if cart == None:
                ans = {}
                ans["message"] = "SUCCESS"
                ans["total_qty"] = 0
                ans["total_price"] = 0
                ans["data"] = []
                return ans, 200

            detail = DetailCart.query.filter_by(id_cart = cart.id, status = True)
            
            ans = {}
            ans["message"] = "SUCCESS"
            ans["total_qty"] = cart.total_qty
            ans["total_price"] = cart.total_price
            rows = []
            for row in detail.all():
                rows.append(marshal(row, self.cart_detail_field))
            
            ans["data"] = rows
            return ans, 200

        elif args['status'] == True:
            cart = cart.filter_by(id_user = current_user, status = True).order_by('updatedAt desc').all()
            
            all_data = []
            for data in cart:
                ans = marshal(data, self.cart_field)
                
                detail = DetailCart.query.filter_by(id_cart = data.id, status = True)
                rows = []
                for row in detail.all():
                    rows.append(marshal(row, self.cart_detail_field))
                
                ans["datas"] = rows
                all_data.append(ans)
            
            return all_data, 200

    @pelapak_required
    def post(self, id):
        current_user = get_jwt_identity()
        cart = Cart.query.filter_by(id_user = current_user, status = False).first()
        if cart == None:
            cart = Cart(id_user = current_user)
            db.session.add(cart)
            db.session.commit()
        
        cart_id =  cart.id

        price = Buku.query.get(id).harga

        detail = DetailCart.query.filter_by(id_cart = cart_id, id_buku = id, status = True).first()
        if detail == None:
            detail = DetailCart(id_cart = cart_id, id_buku = id, qty = 1, price = price)
        else:
            detail.qty = detail.qty + 1
            detail.updatedAt = db.func.current_timestamp()
        db.session.add(detail)
        db.session.commit()

        cart.total_qty = cart.total_qty + 1
        cart.total_price = cart.total_price + price
        cart.updatedAt = db.func.current_timestamp()
        db.session.add(cart)
        db.session.commit()

        return {"message": "SUCCESS"}, 200

    @pelapak_required
    def patch(self, id):

        current_user = get_jwt_identity()
        cart = Cart.query.filter_by(id_user = current_user, status = False).first()

        parser = reqparse.RequestParser()
        parser.add_argument("action", type= str, help= 'action not exist', location= 'json', choices= ("tambah_qty", "kurang_qty", "bayar", "delete"), required= False)
        args = parser.parse_args()

        if args['action'] == "tambah_qty":
            price = Buku.query.get(id).harga
            cart.total_qty = cart.total_qty + 1
            cart.total_price = cart.total_price + price
            cart.updatedAt = db.func.current_timestamp()
            db.session.add(cart)
            db.session.commit()

            detail = DetailCart.query.filter_by(id_cart = cart.id, id_buku = id, status= True).first()
            detail.qty = detail.qty + 1
            detail.updatedAt = db.func.current_timestamp()
            db.session.add(detail)
            db.session.commit()

        elif args['action'] == "kurang_qty":
            price = Buku.query.get(id).harga
            cart.total_qty = cart.total_qty - 1
            cart.total_price = cart.total_price - price
            cart.updatedAt = db.func.current_timestamp()
            db.session.add(cart)
            db.session.commit()

            detail = DetailCart.query.filter_by(id_cart = cart.id, id_buku = id, status= True).first()
            detail.qty = detail.qty - 1
            detail.updatedAt = db.func.current_timestamp()
            db.session.add(detail)
            db.session.commit()

        elif args['action'] == "bayar":
            cart.status = True
            cart.updatedAt = db.func.current_timestamp()
            db.session.add(cart)
            db.session.commit()

        elif args['action'] == "delete":
            price = Buku.query.get(id).harga

            detail = DetailCart.query.filter_by(id_cart = cart.id, id_buku = id, status= True).first()
            detail.status = False
            detail.updatedAt = db.func.current_timestamp()
            db.session.add(detail)
            db.session.commit()

            cart.total_qty = cart.total_qty - detail.qty
            cart.total_price = cart.total_price - (detail.qty * price)
            cart.updatedAt = db.func.current_timestamp()
            db.session.add(cart)
            db.session.commit()

        return {'message': "SUCCESS"}, 200


# Users Endpoint
api.add_resource(LoginResource, '/api/users/login', '/api/users/me')
api.add_resource(RegisterResource, '/api/users/register', '/api/users/register/<path:act>')

# Pelapak Endpoint
api.add_resource(AuthorResource, '/api/users/items', '/api/users/items/<int:id>')

# Public Endpoint
api.add_resource(PublicResource, '/api/public/items', '/api/public/items/<int:id>' )

# Kategori Endpoint
api.add_resource(KategoriResource, '/api/public/kategori', '/api/public/kategori/<int:id>' )

# Cart Endpint
api.add_resource(CartResource, '/api/users/cart', '/api/users/cart/<int:id>' )


@jwt.expired_token_loader
def exipred_token_message():
    return json.dumps({"message": "The token has expired"}), 401, {'Content-Type': 'application/json'}

@jwt.unauthorized_loader
def unathorized_message(error_string):
    return json.dumps({'message': error_string}), 401, {'Content-Type': 'application/json'}


if __name__ == "__main__":
    try:
        if sys.argv[1] == 'db':
            manager.run()
    except IndexError as identifier:
        # app.run(debug=True, host='0.0.0.0', port=5000, ssl_context='adhoc')
        app.run(debug=True, host='0.0.0.0', port=5000)