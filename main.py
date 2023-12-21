from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from fastapi import Request, Body, BackgroundTasks, FastAPI, HTTPException, status, Response, Depends
from fastapi_sessions.backends.implementations import InMemoryBackend
from fastapi_sessions.session_verifier import SessionVerifier
from fastapi_sessions.frontends.implementations import SessionCookie, CookieParameters
from pydantic import BaseModel
from uuid import UUID, uuid4
import binascii
import hashlib
import os
import sqlite3


class SessionData(BaseModel):
    username: str
    N: int = 0
    b: int = 0
    A: int = 0
    B: int = 0
    g: int = 0
    S: int = 0
    K: bytes = b""
    M: bytes = b""

class BasicVerifier(SessionVerifier[UUID, SessionData]):
    def __init__(
        self,
        *,
        identifier: str,
        auto_error: bool,
        backend: InMemoryBackend[UUID, SessionData],
        auth_http_exception: HTTPException,
    ):
        self._identifier = identifier
        self._auto_error = auto_error
        self._backend = backend
        self._auth_http_exception = auth_http_exception

    @property
    def identifier(self):
        return self._identifier

    @property
    def backend(self):
        return self._backend

    @property
    def auto_error(self):
        return self._auto_error

    @property
    def auth_http_exception(self):
        return self._auth_http_exception

    def verify_session(self, model: SessionData) -> bool:
        """If the session exists, it is valid"""
        return True

cookie_params = CookieParameters()

cookie = SessionCookie(
    cookie_name="cookie",
    identifier="general_verifier",
    auto_error=True,
    secret_key=os.environ.get('SECRET_KEY', 'DONOTUSE'),
    cookie_params=cookie_params,
)
backend = InMemoryBackend[UUID, SessionData]()

verifier = BasicVerifier(
    identifier="general_verifier",
    auto_error=True,
    backend=backend,
    auth_http_exception=HTTPException(
        status_code=403, detail="invalid session"),
)

DB_NAME = os.environ.get('DB_NAME', 'db.db')
app = FastAPI()
sessions = {}
DEBUG = True


def get_database():
    return sqlite3.connect(DB_NAME)

def generate_salt(length=16):
    return binascii.hexlify(os.urandom(length)).decode()

def generate_random_number(length=32):
    return int.from_bytes(os.urandom(length), byteorder="big")

def SHA(input_string, as_bytes=False):
    input_bytes = input_string
    if isinstance(input_string, str):
        input_bytes = input_string.encode()
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_bytes)
    if as_bytes:
        return sha256_hash.digest()
    return sha256_hash.hexdigest()

def generate_srp_parameters():
    parameters = dh.generate_parameters(
        generator=2, key_size=2048, backend=default_backend()
    )
    p = parameters.parameter_numbers().p
    g = parameters.parameter_numbers().g
    return {"N": p, "g": g}

def create_user(username: str, password: str):
    salt = generate_salt()
    inner_hash = SHA(f"{username}:{password}")
    x = int(SHA(f"{salt}{inner_hash}"), 16)
    parameters = generate_srp_parameters()
    N = parameters.get("N")
    g = parameters.get("g")
    password_verification = pow(g, x, N)
    query = 'INSERT INTO users (USERNAME, PASSWORD_VERIFICATION, N, g, salt) VALUES (?, ?, ?, ?, ?)'
    database = get_database()
    database.execute(query, (username, str(password_verification), str(N), str(g), salt,))
    database.commit()
    database.close()

@app.put("/signup")
async def signup(
    background_tasks: BackgroundTasks,
    username: str = Body(...),
    password: str = Body(...),
):
    database = get_database()
    query = 'SELECT * FROM users WHERE username=?'
    cursor = database.cursor()
    row = cursor.execute(query, (username,)).fetchone()
    if row:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"message": "Username already exists"},
        )
    background_tasks.add_task(
        create_user, username=username, password=password)

    cursor.close()
    database.close()
    return {
        "message": "User registered successfully, please wait for a few minutes..."
    }

@app.post("/signin/initial")
async def initial_signin(request: Request, response: Response):
    form = await request.json()
    username = form.get("username")
    database = get_database()
    query = f'SELECT N, g, salt FROM users WHERE username=?'
    cursor = database.cursor()
    row = cursor.execute(query, (username,)).fetchone()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"message": "Username/Password did not exists"},
        )
    (N, g, salt) = row
    N = int(N)
    g = int(g)
    session = uuid4()
    data = SessionData(username=username, N=N, g=g)
    await backend.create(session, data)
    cookie.attach_to_response(response, session)
    cursor.close()
    database.close()
    return {"N": N, "g": g, "salt": salt}

@app.post("/signin/getpubkey", dependencies=[Depends(cookie)])
async def getpubkey(
    session_data: SessionData = Depends(verifier),
    request: Request = Request,
    session_id: UUID = Depends(cookie),
):
    form = await request.json()
    A = form.get("A")
    username = session_data.username
    N = session_data.N
    g = session_data.g
    b = generate_random_number()
    if A % N == 0:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid client public key: A % N is zero. Aborting authentication."
            if DEBUG
            else "Login failed",
        )
    database = get_database()
    query = f'SELECT PASSWORD_VERIFICATION FROM users WHERE username=?'
    cursor = database.cursor()
    row = cursor.execute(query, (username,)).fetchone()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"message": "Username/Password did not exists"},
        )
    v = int(row[0])
    B = (v + pow(g, b, N)) % N
    A_bytes = A.to_bytes((A.bit_length() + 7) // 8, byteorder="big")
    B_bytes = B.to_bytes((B.bit_length() + 7) // 8, byteorder="big")
    u = int(hashlib.sha256(A_bytes + B_bytes).hexdigest(), 16)
    vu_mod_N = pow(v, u, N)
    S = pow(A * vu_mod_N, b, N)
    K = SHA(str(S))
    session_data.K = K
    await backend.update(session_id, session_data)
    cursor.close()
    database.close()
    return {"B": B}

@app.post("/signin/exchange_proof", dependencies=[Depends(cookie)])
async def exchange_proof(
    session_data: SessionData = Depends(verifier),
    request: Request = Request,
    session_id: UUID = Depends(cookie),
):
    form = await request.json()
    K_client = form.get("K").encode("utf-8")
    M = form.get("M").encode("utf-8")
    K_server = session_data.K.encode("utf-8")
    A = session_data.A
    username = session_data.username
    if K_server != K_client:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"message": "K_server != K_client" if DEBUG else "Login failed"},
        )
    A_bytes = A.to_bytes((A.bit_length() + 7) // 8, byteorder="big")
    M_Server = SHA(A_bytes + M + K_server)
    await backend.delete(session_id)
    sessions[M_Server] = {"username": username}
    return {"M": M_Server}

@app.get("/whoami", dependencies=[Depends(cookie)])
async def whoami(request: Request = Request):
    token = request.cookies.get("X-Auth-Token")
    if token not in sessions:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "message": "Server does not recognise client"
                if DEBUG
                else "Unauthorised"
            },
        )
    return {"message": f'Hello, {sessions.get(token).get("username")}'}
