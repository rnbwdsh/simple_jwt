from typing import Optional, Dict
from fastapi import HTTPException

import jwt


def jwt_username(authorize, request) -> Optional[str]:
    if cookie := request.cookies.get(authorize._access_cookie_key):  # noqa
        return jwt.decode(cookie, options={"verify_signature": False})["sub"]


def jwt_algo(authorize, request) -> Optional[str]:
    if cookie := request.cookies.get(authorize._access_cookie_key):  # noqa
        return jwt.get_unverified_header(cookie)["alg"]
    else:
        raise ValueError("No jwt or alg")


def jwt_signature(payload: Dict, algo: str) -> Optional[bytes]:
    if algo == "":
        raise HTTPException(status_code=418, detail=list(payload.keys()))
    tok = jwt.encode(payload, "", algorithm=algo).decode()
    return tok.split(".")[2]
