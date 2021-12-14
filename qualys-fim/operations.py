""" 
Copyright start 
Copyright (C) 2008 - 2021 Fortinet Inc. 
All rights reserved. 
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE 
Copyright end 
"""

import requests

from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('qualys-fim')


class QualysFIM(object):
    def __init__(self, config):
        self.server_url = config.get('server_url')
        if not self.server_url.startswith('https://'):
            self.server_url = 'https://' + self.server_url
        if not self.server_url.endswith('/'):
            self.server_url += '/'
        self.username = config.get('username')
        self.password = config.get('password')
        self.verify_ssl = config.get('verify_ssl')

    def make_request(self, endpoint=None, method='GET', data=None, params=None, files=None, headers=None):
        try:
            url = self.server_url + endpoint
            response = requests.request(method, url, params=params, files=files, data=data, headers=headers,
                                        verify=self.verify_ssl)
            if response.status_code == 201 or response.status_code == 200:
                return response.json()
            else:
                logger.error(response.text)
                raise ConnectorError({'status_code': response.status_code, 'message': response.reason})
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError('The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid endpoint or credentials')
        except Exception as err:
            logger.exception(str(err))
            raise ConnectorError(str(err))


def generate_authentication_token(config):
    try:
        endpoint = config.get('server_url') + '/auth'
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        data = {'username': config.get('username'), 'password': config.get('password'), 'token': True}
        token = requests.post(url=endpoint, headers=headers, data=data).text
        headers = {'Authorization': F'Bearer {token}', 'content-type': 'application/json'}
        if 'authentication_exceptions' in headers['Authorization']:
            raise Exception("Authentication Failure: Your account is not recognized and cannot login at this time.")
        return headers
    except Exception as e:
        logger.exception('{}'.format(e))
        raise ConnectorError('{}'.format(e))


def get_events(config, params):
    fim = QualysFIM(config)
    request_payload = {k: v for k, v in params.items() if v is not None and v != '' and v != {} and v != []}
    endpoint = 'fim/v2/events/search'
    headers = generate_authentication_token(config)
    return fim.make_request(endpoint=endpoint, method='POST', data=request_payload, headers=headers)


def get_event_details(config, params):
    fim = QualysFIM(config)
    endpoint = 'fim/v2/events/{eventId}'.format(eventId=params.get('eventId'))
    headers = generate_authentication_token(config)
    return fim.make_request(endpoint=endpoint, headers=headers)


def create_manual_incident(config, params):
    fim = QualysFIM(config)
    request_payload = {
        "name": params.get('name'),
        "reviewers": [
            params.get('reviewers', '')
        ],
        "filters": [
            params.get('filter')
        ],
        "comment": params.get('comment', ''),
        "type": "DEFAULT"
    }
    if params.get('userInfo'):
        request_payload.update({
            "userInfo": {
                "user": {
                    "name": params.get('userName'),
                    "id": params.get('userId')
                }
            }
        }
        )
    endpoint = 'fim/v3/incidents/create'
    headers = generate_authentication_token(config)
    return fim.make_request(endpoint=endpoint, method='POST', data=request_payload, headers=headers)


def approve_incident(config, params):
    fim = QualysFIM(config)
    request_payload = {k: v for k, v in params.items() if v is not None and v != '' and v != {} and v != []}
    endpoint = 'fim/v3/incidents/{incidentId}/approve'.format(incidentId=request_payload.pop('incidentId'))
    headers = generate_authentication_token(config)
    return fim.make_request(endpoint=endpoint, method='POST', data=request_payload, headers=headers)


def get_incidents(config, params):
    fim = QualysFIM(config)
    request_payload = {k: v for k, v in params.items() if v is not None and v != '' and v != {} and v != []}
    endpoint = 'fim/v3/incidents/search'
    headers = generate_authentication_token(config)
    return fim.make_request(endpoint=endpoint, method='POST', data=request_payload, headers=headers)


def fetch_incident_events(config, params):
    fim = QualysFIM(config)
    request_payload = {k: v for k, v in params.items() if v is not None and v != '' and v != {} and v != []}
    endpoint = 'fim/v2/incidents/{incidentId}/events/search'.format(incidentId=request_payload.pop('incidentId'))
    headers = generate_authentication_token(config)
    return fim.make_request(endpoint=endpoint, method='POST', data=request_payload, headers=headers)


def get_assets(config, params):
    fim = QualysFIM(config)
    request_payload = {k: v for k, v in params.items() if v is not None and v != '' and v != {} and v != []}
    endpoint = 'fim/v3/assets/search'
    headers = generate_authentication_token(config)
    return fim.make_request(endpoint=endpoint, method='POST', data=request_payload, headers=headers)


def _check_health(config):
    try:
        params = {}
        res = get_assets(config, params)
        if res:
            logger.info('connector available')
            return True
    except Exception as e:
        logger.exception('{}'.format(e))
        raise ConnectorError('{}'.format(e))


operations = {
    'get_events': get_events,
    'get_event_details': get_event_details,
    'create_manual_incident': create_manual_incident,
    'approve_incident': approve_incident,
    'get_incidents': get_incidents,
    'fetch_incident_events': fetch_incident_events,
    'get_assets': get_assets
}
