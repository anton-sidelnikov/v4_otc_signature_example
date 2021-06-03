import hashlib
import hmac
import json
import os
from datetime import datetime
from urllib.parse import urlparse

import requests

SIGV4_TIMESTAMP = '%Y%m%dT%H%M%SZ'
sign_algorithm_HMAC_SHA_256 = 'SDK-HMAC-SHA256'
AK = os.getenv('AWS_ACCESS_KEY_ID')
SK = os.getenv('AWS_SECRET_ACCESS_KEY')


def sorted_stringified_headers(hdrs):
    res = []
    for k, v in hdrs.items():
        res.append(f'{k.lower()}:{v}')
    res.sort()
    return res


def get_signed_headers(hdrs):
    signed_headers = ''
    for value in hdrs:
        signed_headers += value.split(':')[0] + ';'
    return signed_headers[:-1]


def get_query_string(access_key, region, signed_headers, service, iso8601):
    yyyymmdd = iso8601[:8]
    query_string = sign_algorithm_HMAC_SHA_256
    query_string += f' Credential={access_key}/{yyyymmdd}/{region}/{service}/sdk_request,'
    query_string += f' SignedHeaders={signed_headers},'
    return query_string, yyyymmdd


def get_canonical_request(url, method, body, stringified_headers, signed_headers):
    path = url.path
    body_hash = hashlib.sha256(body.encode()).hexdigest()
    if not path:
        path = '/'
    if not path.endswith('/'):
        path += '/'
    if not path.startswith('/'):
        path = '/' + path
    canonical_request = f'{method.upper()}\n{path}\n{url.query}\n'
    for header in stringified_headers:
        canonical_request += f'{header}\n'
    canonical_request += f'\n{signed_headers}\n{body_hash}'
    return canonical_request


def get_string_to_sign(iso8601, yyyymmdd, region, service, hash):
    return f'{sign_algorithm_HMAC_SHA_256}\n{iso8601}\n{yyyymmdd}/{region}/{service}/sdk_request\n{hash.hexdigest()}'


def sign(key, msg, hex=False):
    if hex:
        return hmac.new(key, msg.encode(), hashlib.sha256).hexdigest()
    else:
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def get_signing_key(secret_key, yyyymmdd, region, service):
    k_date = sign(f'SDK{secret_key}'.encode(), yyyymmdd)
    k_region = sign(k_date, region)
    k_service = sign(k_region, service)
    return sign(k_service, 'sdk_request')


def get_signature(key, string_to_sign):
    return sign(key, string_to_sign, hex=True)


def get_sign_headers(url, headers, access_key, secret_key, date=None,
                     method='GET', service_name='', region_name='', body=''):
    if not date:
        datetime_now = datetime.utcnow()
        timestamp = datetime_now.strftime(SIGV4_TIMESTAMP)
    else:
        timestamp = date.strftime(SIGV4_TIMESTAMP)
    parsed_url = urlparse(url)
    headers['Host'] = parsed_url.hostname
    headers['X-Sdk-Date'] = timestamp
    stringified_headers = sorted_stringified_headers(headers)
    signed_headers = get_signed_headers(stringified_headers)
    query_string, yyyymmdd = get_query_string(
        access_key=access_key,
        region=region_name,
        signed_headers=signed_headers,
        service=service_name,
        iso8601=timestamp
    )
    canonical_request = get_canonical_request(
        url=parsed_url,
        stringified_headers=stringified_headers,
        signed_headers=signed_headers,
        method=method,
        body=body
    )
    hash = hashlib.sha256(canonical_request.encode())
    string_to_sign = get_string_to_sign(
        iso8601=timestamp,
        yyyymmdd=yyyymmdd,
        region=region_name,
        service=service_name,
        hash=hash
    )
    signature_key = get_signing_key(
        secret_key=secret_key,
        yyyymmdd=yyyymmdd,
        region=region_name,
        service=service_name
    )
    signature = get_signature(
        key=signature_key,
        string_to_sign=string_to_sign
    )
    return {
        'X-Sdk-Date': timestamp,
        'Authorization': f'{query_string} Signature={signature}'
    }


if __name__ == '__main__':
    project_id = ''
    endpoint = ''
    iam_url = 'https://iam.eu-de.otc.t-systems.com/v3/projects'
    headers = {
        'User-Agent': 'OpenTelekomCloud PyClient/v1.0',
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Host': 'iam.eu-de.otc.t-systems.com',
    }
    signed_headers = get_sign_headers(
        url=iam_url,
        method='get',
        access_key=AK,
        secret_key=SK,
        headers=headers,
    )
    headers.update(signed_headers)
    auth = requests.get(iam_url, headers=headers)
    projects = json.loads(auth.text)
    print(projects)

    topics_url = f'https://smn.eu-de.otc.t-systems.com/v2/{project_id}/notifications/topics'
    headers = {
        'User-Agent': 'OpenTelekomCloud PyClient/v1.0',
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Host': 'smn.eu-de.otc.t-systems.com',
    }
    signed_headers = get_sign_headers(
        url=topics_url,
        method='get',
        access_key=AK,
        secret_key=SK,
        headers=headers
    )
    headers.update(signed_headers)
    topics = requests.get(topics_url, headers=headers)
    topics = json.loads(topics.text)
    print(topics)

    smn_url = f'https://smn.eu-de.otc.t-systems.com/v2/{project_id}/notifications/sms'
    headers = {
        'User-Agent': 'OpenTelekomCloud PyClient/v1.0',
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Host': 'smn.eu-de.otc.t-systems.com',
    }
    body = {
        'endpoint': f'{endpoint}',
        'message': 'SMS message test'
    }
    signed_headers = get_sign_headers(
        url=smn_url,
        method='post',
        access_key=AK,
        secret_key=SK,
        headers=headers,
        body=json.dumps(body)
    )
    headers.update(signed_headers)
    send_sms = requests.post(smn_url, headers=headers, json=body)
    sms = json.loads(send_sms.text)
    print(sms)
