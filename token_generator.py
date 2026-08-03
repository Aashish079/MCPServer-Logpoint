import argparse
import datetime
import jwt


def generate_jwt(sub: str, scope: str, secret: str, alg: str = "HS256", iat=None, exp=None) -> str:
    iat = iat or datetime.datetime.utcnow()
    exp = exp or (iat + datetime.timedelta(hours=1))
    payload = {"sub": sub, "scope": scope, "iat": iat, "exp": exp, "iss": "self-signed"}
    return jwt.encode(payload, secret, algorithm=alg)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a self-signed JWT for Logpoint Alert Rule API tests.")
    parser.add_argument("--sub", required=True)
    parser.add_argument("--scope", required=True)
    parser.add_argument("--secret", required=True)
    parser.add_argument("--alg", default="HS256")
    args = parser.parse_args()
    print(generate_jwt(args.sub, args.scope, args.secret, args.alg))
