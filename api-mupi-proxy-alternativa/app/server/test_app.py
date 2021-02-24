"""
Create functions with a name that starts with test_ (this is standard pytest conventions).

Use the TestClient object the same way as you do with requests.

Write simple assert statements with the standard Python expressions that you need to check (again, standard pytest).

pytest
"""
from typing import Optional
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from fastapi.testclient import TestClient
from .server import app

from .models.provider import (
    ErrorResponseModel,
    ResponseModel,
    Provider,
    UpdateProvider,
)
from .models.murtentry import (
    ErrorResponseModel,
    ResponseModel,
    MurtEntry,
    UpdateMurtEntry,
)
from .models.sdncontroller import (
    ErrorResponseModel,
    ResponseModel,
    SDNController,
    UpdateSDNController,
)

client = TestClient(app)


def test_read_main():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"Welcome to":"MUPI-PROXY"}


def test_read_item():
    response = client.get("/items/foo")
    assert response.status_code == 200
    assert response.json() == {
        "id": "foo",
        "title": "Foo",
        "description": "There goes my hero",
    }


def test_read_item_bad_token():
    response = client.get("/items/foo")
    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid X-Token header"}


def test_read_inexistent_item():
    response = client.get("/items/baz")
    assert response.status_code == 404
    assert response.json() == {"detail": "Item not found"}


def test_create_item():
    response = client.post(
        "/items/",
        json={"id": "foobar", "title": "Foo Bar", "description": "The Foo Barters"},
    )
    assert response.status_code == 200
    assert response.json() == {
        "id": "foobar",
        "title": "Foo Bar",
        "description": "The Foo Barters",
    }


def test_create_item_bad_token():
    response = client.post(
        "/items/",
        json={"id": "bazz", "title": "Bazz", "description": "Drop the bazz"},
    )
    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid X-Token header"}


def test_create_existing_item():
    response = client.post(
        "/items/",
        json={
            "id": "foo",
            "title": "The Foo ID Stealers",
            "description": "There goes my stealer",
        },
    )
    assert response.status_code == 400
    assert response.json() == {"detail": "Item already exists"}
