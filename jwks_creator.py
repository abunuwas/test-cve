import os
import subprocess
from jwcrypto import jwk

key_name = "service_app_keys"  # change as required
key_type = "RSA"
alg = "RSA256"
size = 2048
use = "sig"


def create_keys(key_name):
    """Create all of the keys and save in keys directory"""
    key = jwk.JWK.generate(kty=key_type, size=size, kid=key_name, use=use, alg=alg)

    with open(f"keys/{key_name}_private.json", "w") as writer:
        writer.write(key.export_private())

    with open(f"keys/{key_name}_public.json", "w") as writer:
        writer.write(key.export_public())

    with open(f"keys/{key_name}.pem", "w") as writer:
        writer.write(key.export_to_pem("private_key", password=None).decode("utf-8"))

    # Output private key to RSA format for Terraform using openssl
    args = [
        "openssl",
        "rsa",
        "-in",
        f"keys/{key_name}.pem",
        "-out",
        f"keys/{key_name}_rsa.pem",
    ]
    subprocess.run(args)


if not os.path.exists("keys"):
    os.makedirs("keys")
    create_keys(key_name=key_name)
    print("Keys created. Please move to secure storage and remove the keys directory.")
else:
    print(
        "Please remove existing keys directory- make sure you have the existing keys stored securely because this will generate new ones!"
    )
