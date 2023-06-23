import jwt
from fastapi import Request, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import time
import base64
import os
JWT_SECRET = os.environ.get("JWT_SECRET")


def decodeJWT(token: str) -> dict:
    try:
        decoded_token = jwt.decode(
            token, JWT_SECRET, algorithms=["HS256"], options={"verify_aud": False})
        return decoded_token if (decoded_token["exp"] >= time.time() and (decoded_token["role"] == "authenticated" or decoded_token["role"] == "service_role")) else None
    except Exception as e:
        print(e)
        return {}


class JWTBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super(JWTBearer, self).__init__(auto_error=auto_error)

    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = await super(JWTBearer, self).__call__(request)
        if credentials:
            if not credentials.scheme == "Bearer":
                raise HTTPException(
                    status_code=403, detail="Invalid authentication scheme.")
            if not self.verify_jwt(credentials.credentials):
                raise HTTPException(
                    status_code=403, detail="Invalid token or expired token.")
            return credentials.credentials
        else:
            raise HTTPException(
                status_code=403, detail="Invalid authorization code.")

    def verify_jwt(self, jwtoken: str) -> bool:
        isTokenValid: bool = False

        try:
            payload = decodeJWT(jwtoken)
        except:
            payload = None
        if payload:
            isTokenValid = True
        return isTokenValid
