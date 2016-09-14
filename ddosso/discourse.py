import urllib.parse
from hashlib import sha256
import hmac
from base64 import b64decode, b64encode, decodebytes, encodebytes


def sso_validate(payload, signature, secret):
    payload = urllib.parse.unquote(payload)
    computed_sig = hmac.new(
        secret.encode('utf-8'),
        payload.encode('utf-8'),
        sha256
    ).hexdigest()
    return hmac.compare_digest(computed_sig, signature)


def sso_has_nounce(payload):
    payload = urllib.parse.unquote(payload)
    decoded = decodebytes(payload.encode('utf-8')).decode('utf-8')
    return 'nonce' in decoded


def get_sso_data(payload):
    decoded = decodebytes(payload.encode('utf-8')).decode('utf-8')
    return dict(data.split("=") for data in decoded.split('&'))


def build_sso_login_url(nonce, redirect_uri, secret):
    data = {
        'nonce': nonce,
        'return_sso_url': redirect_uri
    }

    payload = urllib.parse.urlencode(data)
    payload = b64encode(payload.encode())
    sig = hmac.new(secret.encode('utf-8'), payload, sha256).hexdigest()

    return '/session/sso_provider?' + urllib.parse.urlencode(
        {'sso': payload, 'sig': sig})
