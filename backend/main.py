from typing import Union
from fastapi import FastAPI
from pydantic import BaseModel
import pymongo
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

dbClient = pymongo.MongoClient()
db = dbClient["infra"]
providers = db["providers"]


@app.get("/")
def read_root():
    return {"infra-api": "0.1.0"}


@app.get("/providers")
def read_items():
    return {"providers": providers.find()}


@app.get("/providers/{provider_id}")
def read_items(provider_id: str):
    return {"provider": providers.find_one({"id": provider_id})}


class Item(BaseModel):
    name: str
    price: float


@app.put("/items/{item_id}")
def update_item(item_id: int, item: Item):
    return {"item_name": item.name, "item_id": item_id}
