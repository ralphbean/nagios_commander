#!/usr/bin/env python2

import re
from urlparse import urlparse, parse_qs
import sys

import bs4
import requests


session = requests.session()


def _parse_service_form(response):
    parsed = bs4.BeautifulSoup(response.text, "lxml")
    inputs = {}
    for child in parsed.form.find_all(name='input'):
        if child.attrs['type'] == 'submit':
            continue
        inputs[child.attrs['name']] = child.attrs['value']
    return (parsed.form.attrs['action'], inputs)


def login(url, username, password):
    fedora_openid_api = r'https://id.fedoraproject.org/api/v1/'
    fedora_openid = r'^http(s)?:\/\/id\.(|stg.|dev.)?fedoraproject'\
        '\.org(/)?'
    motif = re.compile(fedora_openid)

    # Try to access the service, but get redirect to ipsilon.
    response = session.get(url)

    if '<title>OpenID transaction in progress</title>' in response.text:
        # requests.session should hold onto this for us....
        _url, data = _parse_service_form(response)
        if not motif.match(_url):
            raise Exception( 'Un-expected openid provider asked: %s' % _url)
    elif 'Nagios Enterprises' in response.text:
        # User already logged in?
        raise "unpossible."
    else:
        data = {}
        for resp in response.history:
            if motif.match(resp.url):
                parsed = parse_qs(urlparse(resp.url).query)
                for key, value in parsed.items():
                    data[key] = value[0]
                break
        else:
            raise Exception('Unable to determine openid parameters.')

    # Contact openid provider
    data['username'] = username
    data['password'] = password
    # Let's precise to FedOAuth that we want to authenticate with FAS
    data['auth_module'] = 'fedoauth.auth.fas.Auth_FAS'

    response = session.post(fedora_openid_api, data=data)
    if not bool(response):
        raise Exception("Failed %r for %r" % (response, response.url))
    output = response.json()

    if not output['success']:
        raise Exception(output['message'])

    url = output['response']['openid.return_to']
    response = session.get(url, params=output['response'])
    if not bool(response):
        raise Exception("Failed %r for %r" % (response, response.url))

    return output


if __name__ == '__main__':
    url, username = sys.argv[1:]
    #sys.stderr.write('Password:  ')
    #password = sys.stdin.read().strip('\n')
    # Annoying...
    import commands
    password = commands.getoutput('pass sys/fas')

    _ = login(url, username, password)

    # Verify that we are actually logged in.
    response = session.get(url)
    # BUT THIS FAILS!
    expected = 'admin.fedoraproject.org'
    error_msg = "%r not in %r" % (expected, response.url)
    assert expected in response.url, error_msg

    # print these out to use them later with 'cURL'
    cookies = "; ".join([
        '%s=%s' % (key, value)
        for key, value in session.cookies.items()
        if key == 'open_id_session_id'
    ])
    print('--cookie %s' % cookies)
