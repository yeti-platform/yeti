from datetime import datetime, timedelta

import jwt
from flask import current_app, session


def generate_session_token(user):
    token = jwt.encode(
        {
            "sub": user.username,
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(days=30),
        },
        current_app.config["SECRET_KEY"],
    )

    session.clear()
    session["token"] = token
    user.session_token = token

    return user.save()
