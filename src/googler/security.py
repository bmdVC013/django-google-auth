import base64
import hashlib
import os


def generate_state():
  state = base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8").replace("=", "")
  
  return state


def generate_pkce_pair():
  code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode("utf-8")
  code_verifier = code_verifier.replace("=", "")

  code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
  code_challenge = base64.urlsafe_b64encode(code_challenge).decode("utf-8")
  code_challenge = code_challenge.replace("=", "")

  return code_verifier, code_challenge