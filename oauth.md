OAuth

Users -> localhost:8000/google/login
Your app redirects -> Google -> users logs in to Google
Google -> verifies users, verifies your app -> localhost:8000/google/callback
Your app -> verifies Google callback stuff -> starts users' Django session
