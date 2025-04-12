from urllib.parse import urljoin, urlencode
from django.conf import settings
from django.core.cache import cache
import requests

from . import security

GOOGLE_AUTH_CACHE_KEY_PREFIX = "google:auth:state"
GOOGLE_CLIENT_ID=settings.GOOGLE_CLIENT_ID
GOOGLE_CLIENT_SECRET=settings.GOOGLE_CLIENT_SECRET


def get_cache_key(state):
  return f"{GOOGLE_AUTH_CACHE_KEY_PREFIX}:{state}"


def get_google_auth_callback_url():
  url = urljoin(settings.BASE_URL, settings.GOOGLE_AUTH_CALLBACK_PATH)

  return url


def generate_auth_url():
  google_auth_url = "https://accounts.google.com/o/oauth2/v2/auth"

  redirect_uri = get_google_auth_callback_url()
  state = security.generate_state()
  code_verifier, code_challenge = security.generate_pkce_pair()
  google_auth_client_id = GOOGLE_CLIENT_ID
  scope = " ".join([
    "openid",
    "email",
    "profile",
  ])
  cache_key = get_cache_key(state)

  # Use REDIS caching key-val
  cache.set(cache_key, code_verifier, 30)

  auth_params = {
    "client_id": google_auth_client_id,
    "redirect_uri": redirect_uri,
    "response_type": "code",
    "scope": scope,
    "state": state,
    "code_challenge": code_challenge,
    "code_challenge_method": "S256",
    "access_type": "offline",
    
  }
  encoded_params = urlencode(auth_params)

  return urljoin(google_auth_url, f"?{encoded_params}")


def verify_google_oauth_callback(state, code):
  redirect_uri = get_google_auth_callback_url()
  cache_key = get_cache_key(state)
  code_verifier = cache.get(cache_key)

  if code_verifier is None or code is None or state is None:
    raise Exception("Invalid code or expired code.")

  token_endpoint = "https://oauth2.googleapis.com/token"
  token_data = {
    "code": code,
    "client_id": GOOGLE_CLIENT_ID,
    "client_secret": GOOGLE_CLIENT_SECRET,
    "redirect_uri": redirect_uri,
    "grant_type": "authorization_code",
    "code_verifier": code_verifier,
  }

  r = requests.post(token_endpoint, data=token_data)
  r.raise_for_status()
  
  return r.json()