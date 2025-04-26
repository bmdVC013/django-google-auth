from django.http import HttpResponse
from django.shortcuts import redirect

from . import oauth


def google_login_redirect_view(request):
  google_auth2_url = oauth.generate_auth_url()

  return redirect(google_auth2_url)


def google_login_callback_view(request):
  state = request.GET.get("state")
  code = request.GET.get("code")

  try:
    token_json = oauth.verify_google_oauth_callback(state, code)
  except Exception as e:
    return HttpResponse(f"{e}", state=400)

  google_user_info = oauth.verify_token_json(token_json)
  print(google_user_info)

  return HttpResponse("Now a User Callback")  
