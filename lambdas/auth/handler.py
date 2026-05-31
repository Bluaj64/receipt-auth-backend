import json
import os
import re
import hmac
import hashlib
import secrets
from datetime import datetime, timezone, timedelta

import boto3
from botocore.exceptions import ClientError


dynamodb = boto3.resource("dynamodb")
users_table = dynamodb.Table(os.environ["USERS_TABLE"])
sessions_table = dynamodb.Table(os.environ["SESSIONS_TABLE"])


def response(status_code, body):
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps(body),
    }


def parse_body(event):
    try:
        return json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return None


def is_valid_email(email):
    return re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email) is not None


def validate_password(password):
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return "Password must contain at least one number."
    return None


def hash_password(password, salt_hex=None):
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        100_000,
    )

    return {
        "salt": salt.hex(),
        "passwordHash": password_hash.hex(),
    }

def verify_password(password, salt, stored_password_hash):
    hashed = hash_password(password, salt)

    return hmac.compare_digest(
        hashed["passwordHash"],
        stored_password_hash,
    )

def create_session(email):
    token = secrets.token_urlsafe(32)

    expires_at_dt = datetime.now(timezone.utc) + timedelta(days=7)
    expires_at_epoch = int(expires_at_dt.timestamp())

    sessions_table.put_item(
        Item={
            "token": token,
            "email": email,
            "createdAt": datetime.now(timezone.utc).isoformat(),
            "expiresAt": expires_at_epoch,
        }
    )

    return {
        "token": token,
        "expiresAt": expires_at_dt.isoformat(),
    }

def handle_signup(event):
    body = parse_body(event)

    if body is None:
        return response(400, {"message": "Invalid JSON body."})

    email = str(body.get("email", "")).strip().lower()
    password = str(body.get("password", ""))

    if not email or not password:
        return response(400, {"message": "Email and password are required."})

    if not is_valid_email(email):
        return response(400, {"message": "Invalid email address."})

    password_error = validate_password(password)
    if password_error:
        return response(400, {"message": password_error})

    hashed = hash_password(password)

    try:
        users_table.put_item(
            Item={
                "email": email,
                "passwordHash": hashed["passwordHash"],
                "salt": hashed["salt"],
                "createdAt": datetime.now(timezone.utc).isoformat(),
            },
            ConditionExpression="attribute_not_exists(email)",
        )

    except ClientError as error:
        if error.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return response(409, {"message": "User already exists."})

        print("DynamoDB error:", error)
        return response(500, {"message": "Could not create user."})

    return response(201, {
        "message": "User created successfully.",
        "email": email,
    })

def handle_login(event):
    body = parse_body(event)

    if body is None:
        return response(400, {"message": "Invalid JSON body."})

    email = str(body.get("email", "")).strip().lower()
    password = str(body.get("password", ""))

    if not email or not password:
        return response(400, {"message": "Email and password are required."})

    try:
        result = users_table.get_item(
            Key={"email": email}
        )

    except ClientError as error:
        print("DynamoDB error:", error)
        return response(500, {"message": "Could not log in."})

    user = result.get("Item")

    if not user:
        return response(401, {"message": "Invalid email or password."})

    password_is_valid = verify_password(
        password=password,
        salt=user["salt"],
        stored_password_hash=user["passwordHash"],
    )

    if not password_is_valid:
        return response(401, {"message": "Invalid email or password."})

    session = create_session(email)

    return response(200, {
        "message": "Login successful.",
        "email": email,
        "token": session["token"],
        "expiresAt": session["expiresAt"],
    })
    

def lambda_handler(event, context):
    route = event.get("rawPath")

    if route == "/signup":
        return handle_signup(event)

    if route == "/login":
        return handle_login(event)

    return response(404, {"message": "Route not found."})