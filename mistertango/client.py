import base64
import hashlib
import hmac
import json
from datetime import datetime
from http import HTTPStatus
from time import mktime
from urllib.parse import urlencode

import requests

from . import PaymentException

DEFAULT_BASE_URL = 'https://api.mistertango.com:8445'
SUPPORTED_CURRENCIES = ['EUR']


# https://app.swaggerhub.com/apis-docs/mt1/mistertango-public_api/1.0
class Mistertango:
    # public key
    api_key: str

    # private key
    secret_key: str

    # username/email
    username: str

    # mistertango api endpoint
    api_url: str

    def __init__(self, api_key, secret_key, username, api_url=None):
        self.api_key = api_key
        self.secret_key = secret_key
        self.username = username

        self.api_url = api_url or DEFAULT_BASE_URL

    def _convert_username(self, username):
        return username.replace("@", "%40")

    def _get_nonce(self):
        then = datetime.now()
        epochStr = (mktime(then.timetuple()) * 1e3 + then.microsecond / 1e3) * 10000
        return str(int(epochStr))

    def _make_signature(self, nonce, data, endpoint):
        encoded = (nonce + data).encode()
        message = endpoint.encode() + hashlib.sha256(encoded).digest()

        signature = hmac.new(self.secret_key.encode(), message, hashlib.sha512)

        sigdigest = base64.b64encode(signature.digest())

        return sigdigest.decode()

    def _prepare_headers(self, nonce, endpoint, data):
        signature = self._make_signature(nonce, data, endpoint)

        return {
            'X-API-KEY': self.api_key,
            'X-API-SIGN': signature,
            'X-API-NONCE': nonce,
            'Content-Type': 'application/x-www-form-urlencoded'}

    def _generate_url(self, endpoint):
        return self.api_url + endpoint

    def _send_request(self, endpoint: str, data: dict):
        nonce = self._get_nonce()
        data['nonce'] = nonce
        post_params = urlencode(data)

        headers = self._prepare_headers(nonce, endpoint, post_params)
        r = requests.post(self._generate_url(endpoint), headers=headers, data=post_params)
        if r.status_code != HTTPStatus.OK:
            raise PaymentException('MisterTango error: {}'.format(r.text))

        return json.loads(r.text)

    def get_balance(self) -> dict:
        '''
        Response example: {
            'available_balance': '4063.27',
            'reservations': 0,
            'real_balance': 4063.27}
        '''
        endpoint = '/v1/transaction/getBalance'

        data = {
            "username": self.username}

        result = self._send_request(endpoint, data)

        return result

    def send_money(self, amount: float, currency: str, recipient: str, account: str,
                   details: str) -> dict:
        '''
        Transfer money from merchant account to recipient account

        :param amount: Amount of money
        :param currency: Currency (only EUR is available)
        :param recipient: Name of the recipient
        :param account: IBAN account number of recipient
        :param details: Details (description) of the transfer
        :return: Mistertango API response

        Example: {
            "status": true,
            "api": {
              "version": "string",
              "title": "string"
            },
            "message": "string",
            "data": "string",
            "duration": 0}
        '''
        endpoint = '/v1/transaction/sendMoney'
        if currency not in SUPPORTED_CURRENCIES:
            # TODO: raise relevant error instead default
            raise AttributeError(
                'Currency not supported. Please use any from this list: {}'.format(
                    SUPPORTED_CURRENCIES))

        data = {
            "username": self.username,
            "amount": amount,
            "currency": currency,
            "recipient": recipient,
            "account": account,
            "details": details}

        # TODO: error handling
        result = self._send_request(endpoint, data)

        return result
