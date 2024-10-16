import json
import urllib.parse
import boto3
import email
import re

print('Loading function')

s3 = boto3.client('s3')
ses = boto3.client('sesv2')
dynamodb = boto3.resource('dynamodb');
ses_rewrite = dynamodb.Table('ses_redirect_rewrite_rules')

class RewriteRule:
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

    def __str__(self):
        attributes = ', '.join(f"{key}: {value}" for key, value in self.__dict__.items())
        return f"RewriteRule({attributes})"

def dynamo_to_python(dynamodb_response : dict) -> RewriteRule:
    return RewriteRule(**dynamodb_response)

def get_python_from_dynamo(key):
    dynamo_response = ses_rewrite.get_item (
        Key={'to_address': key}
    )

    print(f"get_python_from_dynamo: {dynamo_response}")

    item = dynamo_response.get('Item', None)
    print(f"get_python_from_dynamo: {item}")

    if not item:
        return None

    for k, v in item.items():
        print(f"get_python_from_dynamo: {k}: {v}")

    return dynamo_to_python(item)

def get_rewrite_rules(key):
    # Treat 'key' as a complete to-address; <to>@<domain>.
    # If no rewrite rules can be found under that key, 
    # then query for the '@<domain>'.
    
    item = get_python_from_dynamo(key)
    if item:
        return item

    # Try @<domain> for rewrite rules.

    domain = '@' + key.split('@')[1]
    item = get_python_from_dynamo(domain)
    if item:
        return item

    raise KeyError(f"No rewrite rules found for key: {key} or {domain}")

def read_raw_from_s3(bucket, key):
    response = s3.get_object(Bucket=bucket, Key=key)
    print("CONTENT TYPE: " + response['ContentType'])

    raw_email = response['Body'].read().decode('utf-8')
    print("S3 Email: " + raw_email)
    return raw_email

def lambda_handler(event, context):
    print("Received event: " + json.dumps(event, indent=2))

    # Get the object from the event and show its content type
    try:
        if event['Records'][0]['eventSource'] != 'aws:ses':
            # STOP_RULE will continue on te the next rule which should be 
            # reject.
            
            return 'STOP_RULE'
        
        event_headers = event['Records'][0]['ses']['mail']['headers']

        # event_headres is a list of {'name': '...', 'value': '...'} dictionaries
        # Find the 'X-s3-bucket-prefix' header
        bucket = None
        prefix = None

        # SES receiving S3Action writes to the {bucket}/{prefix}/{SMTP id} 
        # where SMTP id is the most recent Received header. Could match on
        # the SES incoming SMTP server but this could change because of the
        # AWS region.
        object_name = None
        for header in event_headers:
            print(f'Header: {header}')

            if header['name'] == 'X-s3-bucket-prefix':
                (bucket, *prefix) = header['value'].split('/')
                prefix = '/'.join(prefix)
            elif (not object_name) and (header['name'] == 'Received'):
                match = re.match(r'.* with SMTP id (.*) for .*', header['value'])
                if match:
                    object_name = match.group(1)

        if not bucket or not prefix:
            raise KeyError(f"Missing header X-s3-bucket-prefix: {bucket}, {prefix}")
        
        if not object_name:
            raise KeyError(f"Missing SMTP id in Received header")

        key = f'{prefix}{object_name}'

        print(f"Bucket: {bucket}, Key: {key}")

        raw_email = read_raw_from_s3(bucket, key)
        msg = email.message_from_string(raw_email)

        rewrite_rules = get_rewrite_rules(msg['To'])

        return_path = rewrite_rules.rewrite_return_path
        msg.replace_header('Return-Path', return_path) if 'Return-Path' in msg else msg.add_header('Return-Path', return_path)

        rewrite_from_address = rewrite_rules.rewrite_from
        if rewrite_from_address == '$return_path':
            rewrite_from_address = return_path

        response = ses.send_email(
            FromEmailAddress = rewrite_from_address,
            ReplyToAddresses = [msg['From']],
            Destination={
                'ToAddresses': [rewrite_rules.rewrite_to_address],  # New envelope recipient
            },
            Content={
                'Raw': {
                    'Data': msg.as_string()  # Original email content, including headers
                }
            }
        )
        print(response)

        return 'CONTINUE'
    
    except Exception as e:
        print(e)
        raise e
