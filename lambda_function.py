import base64
import boto3
import configparser
import json
import logging
import os
import quopri
import re
import sys
import traceback
import urllib.parse
import urllib.request
from time import sleep
from urllib import request
from urllib.error import URLError, HTTPError
from urllib.request import Request, urlopen

s3 = boto3.client('s3')
logger = logging.getLogger()
logger.setLevel(logging.INFO)
config = configparser.ConfigParser()
config.read('./config.ini', 'UTF-8')
BACKET = config.get('aws', 'backet')
SLACK_HOOK_URL = config.get('slack', 'hook_url')
SLACK_API_TOKEN = config.get('slack', 'api_token')
SLACK_CHANNEL = config.get('slack', 'channel')
SLACK_CHANNEL_ID = config.get('slack', 'channel_id')
SLACK_ICON_EMOJI = config.get('slack', 'icon_emoji')
SLACK_COLOR = config.get('slack', 'attachment_color')
SLACK_HISTORY_API = 'https://slack.com/api/channels.history'


def lambda_handler(event, context):
    message_id = event['Records'][0]['ses']['mail']['messageId']
    main(message_id)


def main(message_id):
    print('message id is "{}".'.format(message_id))

    message_data = get_message_data(message_id)
    message_body = get_body_as_plain_text(message_data)
    if message_body == '':
        return {
            'statusCode': 500,
            'body': json.dumps('An error occured.')
        }

    optimized_data = get_optimized_message_data(message_body, message_data)
    post_message_body_to_slack(optimized_data['summary'], message_id)

    if optimized_data['body'] != '':
        thread_ts = get_last_post_ts(message_id)
        post_message_body_to_slack(
            optimized_data['body'], '', thread_ts)

    return {
        'statusCode': 200,
        'body': json.dumps('Process finished.')
    }


def get_message_data(message_id):
    try:
        response = s3.get_object(Bucket=BACKET, Key=message_id)

        message_data = response['Body'].read()
        return message_data.decode('utf-8')
    except Exception:
        print(traceback.format_exc())
        print('Failed to get message object.')
        return ''


def get_body_as_plain_text(message_data):
    try:
        encode_idx = 2
        m = re.search(
            r'Content-Type: text/plain;( charset="?UTF-8"?|[\s\S]*charset=utf-8)\r\nContent-Transfer-Encoding: (base64|quoted-printable)([\s\S]*)(\r\n)+--[\s\S]*Content-', message_data)

        if m is None:
            encode_idx = 1
            m = re.search(
                r'Content-Transfer-Encoding: (base64|quoted-printable)\r\nContent-Type: text/plain;( charset="?UTF-8"?|[\s\S]*charset=utf-8)([\s\S]*)(\r\n)+--[\s\S]*Content-', message_data)

        encode_type = m.group(encode_idx)
        message_body = decode_message_body(m.group(3), encode_type)

        return message_body
    except Exception:
        print(traceback.format_exc())
        print('Failed to get message body as plain text.')
        return ''


def get_body_as_html(message_data):
    try:
        encode_idx = 2
        m = re.search(
            r'Content-Type: text/html;( charset="?UTF-8"?|[\s\S]*charset=utf-8)\r\nContent-Transfer-Encoding: (base64|quoted-printable)([\s\S]*)(\r\n)+--', message_data)

        if m is None:
            encode_idx = 1
            m = re.search(
                r'Content-Transfer-Encoding: (base64|quoted-printable)\r\nContent-Type: text/html;( charset="?UTF-8"?|[\s\S]*charset=utf-8)([\s\S]*)(\r\n)+--', message_data)

        encode_type = m.group(encode_idx)
        message_body = decode_message_body(m.group(3), encode_type)

        return message_body
    except Exception:
        print(traceback.format_exc())
        print('Failed to get message body as html.')
        return ''


def decode_message_body(raw_message_body, encode_type):
    decoded_message_body = ''
    try:
        if encode_type == 'base64':
            encoded_message_body_tmp = raw_message_body.split('\r\n')
            encoded_message_body = ''.join(encoded_message_body_tmp).strip()
            decoded_message_body = base64.b64decode(
                encoded_message_body.encode('utf-8')).decode('utf-8')
        elif encode_type == 'quoted-printable':
            encoded_message_body_tmp = raw_message_body.split('=\r\n')
            encoded_message_body = ''.join(encoded_message_body_tmp).strip()
            decoded_message_body = quopri.decodestring(
                encoded_message_body.encode('utf-8')).decode('utf-8')
    except Exception:
        print(traceback.format_exc())
        print('Failed to decode message body.')

    return decoded_message_body


def get_optimized_message_data(plain_text_message_body, raw_message_data):
    optimized_data = {
        'summary': '',
        'body': ''
    }

    plain_text_message_body = re.sub(
        r'(-+ Forwarded message -+)\r\n', '', plain_text_message_body).strip()

    # add From, Date, Subject if those are not exists
    if re.match(r'From.*<.*>', plain_text_message_body) is None:
        metadata = get_original_metadata(raw_message_data)
        metadata_part = 'From: <{}>\nDate: {}\nSubject: {}\nTo: <{}>\n\n\n'.format(
            metadata['from'], metadata['date'], metadata['subject'], metadata['to'])

        plain_text_message_body = metadata_part + plain_text_message_body

    m_summary = re.search(
        r'(From.*<.*>[\s\S]*To.*<.*>\r?\n)', plain_text_message_body)

    if m_summary is not None:
        optimized_data['summary'] = m_summary.group(1).strip()
        optimized_data['body'] = re.sub(
            r'From.*<.*>[\s\S]*To.*<.*>\r?\n', '', plain_text_message_body).strip()
    else:
        optimized_data['summary'] = plain_text_message_body

    return optimized_data


def get_original_metadata(raw_message_data):
    metadata = {
        'from': '',
        'date': '',
        'subject': '',
        'to': ''
    }

    try:
        m_from = re.search(r'From: <(.*)>', raw_message_data)
        if m_from:
            metadata['from'] = m_from.group(1)

        m_date = re.search(r'Date: (.*)', raw_message_data)
        if m_date:
            metadata['date'] = m_date.group(1)

        m_subject_base64 = re.search(
            r'Subject: =\?UTF-8\?B\?(.*)\?=', raw_message_data)
        if m_subject_base64:
            metadata['subject'] = base64.b64decode(
                m_subject_base64.group(1).encode('utf-8')).decode('utf-8')

        m_to = re.search(r'To: <(.*)>', raw_message_data)
        if m_to:
            metadata['to'] = m_to.group(1)
    except Exception:
        print(traceback.format_exc())

    return metadata


def post_message_body_to_slack(plain_text_message_body, message_id, thread_ts=''):
    post_to_slack(plain_text_message_body, message_id, thread_ts)


def post_to_slack(post_message, message_id, thread_ts=''):
    if post_message == '':
        print('Message body is empty.')
        return False

    if thread_ts == '':
        post_message = '```\n{}\n```\n'.format(post_message)
    else:
        post_message = '{}\n'.format(post_message)

    slack_message = {
        'channel': SLACK_CHANNEL,
        'icon_emoji': SLACK_ICON_EMOJI,
        'attachments': [
            {
                'footer': message_id,
                'color': SLACK_COLOR,
                'fields': [
                    {
                        'value': post_message
                    }
                ]
            }
        ]
    }

    if thread_ts != '':
        slack_message['thread_ts'] = thread_ts

    req = Request(SLACK_HOOK_URL, json.dumps(slack_message).encode('utf-8'))
    try:
        response = urlopen(req)
        response.read()
    except HTTPError as e:
        logger.error("Request failed: %d %s", e.code, e.reason)
    except URLError as e:
        logger.error("Server connection failed: %s", e.reason)


def get_last_post_ts(message_id):
    thread_ts = ''
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    params = {
        'token': SLACK_API_TOKEN,
        'channel': SLACK_CHANNEL_ID,
        'count': 10
    }

    req_url = '{}?{}'.format(SLACK_HISTORY_API, urllib.parse.urlencode(params))
    req = urllib.request.Request(req_url, headers=headers)

    messages = []
    with urllib.request.urlopen(req) as res:
        data = json.loads(res.read().decode("utf-8"))
        if 'messages' in data:
            messages = data['messages']

    for message in messages:
        if 'attachments' in message:
            if message['attachments'][0]['footer'] == message_id:
                thread_ts = message['ts']
                break

    return thread_ts


if __name__ == '__main__':
    print('local debug')
    args = sys.argv
    if len(args) < 2:
        print('First argument for message id is required.')
        quit()

    res = main(args[1])
    print(res)
