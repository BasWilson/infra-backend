import os
import certifi
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from pydantic import BaseModel
import pymongo
from dotenv import load_dotenv
from boto3 import session
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from bcrypt import hashpw, gensalt

load_dotenv()
app = FastAPI()
security = HTTPBasic()

uri = os.getenv("MONGO_URL")
dbClient = pymongo.MongoClient(uri, tlsCAFile=certifi.where())
db = dbClient["infra"]
providers = db["providers"]
users = db["users"]

s3Session = session.Session()
s3Client = s3Session.client(
    "s3",
    region_name=os.getenv("S3_REGION"),
    endpoint_url=os.getenv("S3_ENDPOINT"),
    aws_access_key_id=os.getenv("S3_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("S3_ACCESS_KEY_SECRET"),
)


# BASIC AUTH
def verifyUserPassword(credentials: HTTPBasicCredentials = Depends(security)):
    user = users.find_one({"username": credentials.username})
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )

    if not hashpw(
        credentials.password.encode("utf-8"), user["password"].encode("utf-8")
    ) == user["password"].encode("utf-8"):
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )

    return True


# ROOT
@app.get("/")
def read_root():
    return {"infra-api": "0.1.0", "status": "ok", "docs": "/docs"}


# PROVIDERS
@app.get("/providers")
def read_items():
    res = providers.find({}, {"_id": 0, "name": 1, "wheels": 1})
    return list(res)


@app.get("/providers/{name}")
def read_item(name: str):
    result = providers.find_one({"name": name}, {"_id": 0, "name": 1, "wheels": 1})
    if not result:
        return {"error": "provider not found"}

    versions = s3Client.list_objects_v2(
        Bucket=os.getenv("S3_BUCKET"),
        Prefix="providers/" + name + "/",
    )
    if not versions:
        return {"error": "provider not found"}

    result["baseUrl"] = os.getenv("S3_URL") + "/providers/" + name

    return result


@app.delete("/providers/{name}")
def delete_provider(name: str, _=Depends(verifyUserPassword)):
    result = providers.find_one({"name": name}, {"_id": 0, "name": 1, "wheels": 1})
    if not result:
        return {"error": "provider not found"}

    versions = s3Client.list_objects_v2(
        Bucket=os.getenv("S3_BUCKET"),
        Prefix="providers/" + name + "/",
    )
    if not versions:
        return {"error": "provider not found"}

    for version in versions["Contents"]:
        if version["Key"] != "providers/" + name + "/":
            s3Client.delete_object(
                Bucket=os.getenv("S3_BUCKET"),
                Key=version["Key"],
            )

    providers.delete_one({"name": name})

    return {"success": True}


@app.post("/providers/{name}/{wheel}")
def create_provider(
    file: UploadFile = File(...),
    name: str = "",
    wheel: str = None,
    _=Depends(verifyUserPassword),
):
    if not file:
        return {"error": "missing provider file"}

    if not name:
        return {"error": "missing provider name"}

    if not wheel:
        return {"error": "missing provider wheel"}

    # check if name is alphanumeric
    if not name.isalnum():
        return {"error": "provider name must be alphanumeric"}

    # check if name already exists
    if providers.find_one({"name": name, "wheels": wheel}):
        return {"error": "provider name/wheel already exists"}

    # Upload file to S3
    try:
        s3Client.upload_fileobj(
            file.file,
            os.getenv("S3_BUCKET"),
            "providers/{}/{}".format(name, wheel),
            {
                "ACL": "public-read",
            },
        )
    except Exception as e:
        print(e)
        return {"error": str(e)}

    # check if different version exists
    if providers.find_one({"name": name}):
        providers.update_one({"name": name}, {"$push": {"wheels": wheel}})
    else:
        providers.insert_one(
            {
                "name": name,
                "wheels": [wheel],
            }
        )

    return providers.find_one({"name": name}, {"_id": 0, "name": 1, "wheels": 1})


@app.get("/users/login")
def login(_=Depends(verifyUserPassword)):
    return {"success": True}


# USERS (meant for admin controls, hence why posting is protected)
class UserCreationDto(BaseModel):
    username: str
    password: str


@app.post("/users")
def create_user(dto: UserCreationDto, _=Depends(verifyUserPassword)):
    if not dto.username:
        return {"error": "missing username"}

    if not dto.password:
        return {"error": "missing password"}

    # check if username is alphanumeric
    if not dto.username.isalnum():
        return {"error": "username must be alphanumeric"}

    # check if username already exists
    if users.find_one({"username": dto.username}):
        return {"error": "username already exists"}

    # hash password
    hashedPassword = hashpw(dto.password.encode("utf-8"), gensalt())

    # create user
    users.insert_one(
        {"username": dto.username, "password": hashedPassword.decode("utf-8")}
    )

    return {"success": True}


@app.delete("/users/{username}")
def delete_user(username: str, _=Depends(verifyUserPassword)):
    if not username:
        return {"error": "missing username"}

    # check if username exists
    if not users.find_one({"username": username}):
        return {"error": "username does not exist"}

    # delete user
    users.delete_one({"username": username})

    return {"success": True}
