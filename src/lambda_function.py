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

class StopRuleException(Exception):
    pass

class StopRuleSetException(Exception):
    pass

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

def X_s3_bucket_prefix(value, calling_locals):
    '''
    Extract the bucket and prefix from the header value.

    The header value is expected to be in the format 'bucket/prefix/'.
    '''
    (bucket, *prefix) = value.split('/')
    prefix = '/'.join(prefix)
    return {'bucket': bucket, 'prefix': prefix}

def Received(value, calling_locals):
    '''
    If calling_locals already has an object_name, return an empty dictionary.

    Extract the SMTP id from the Received header value and return it as 
    'object_name'.
    '''
    if 'object_name' in calling_locals:
        return {}
    
    match = re.match(r'.* with SMTP id (.*) for .*', value)
    if match:
        return {'object_name': match.group(1)}
    
    return {}

def X_SES_Spam_Verdict(value, calling_locals):
    '''
    Throw StopRuleException if value is not 'PASS'.

    Stopping the rule should allow the following rule in the set to be executed.
    The following rule should be a reject rule for the same domain.
    '''
    if value.upper() != 'PASS':
        raise StopRuleException(f"Spam verdict is {value}")

    return {}

def X_SES_Virus_Verdict(value, calling_locals):
    '''
    Throw StopRuleException if value is not 'PASS'.

    Stopping the rule should allow the following rule in the set to be executed.
    The following rule should be a reject rule for the same domain.
    '''
    if value.upper() != 'PASS':
        raise StopRuleException(f"Virus verdict is {value}")

    return {}    


def invoke_header_handler(header, calling_scope):
    '''
    Invoke a function in the current scope by the name of the header.
    Replace header '-' with '_'.

    If the function exists, call it with the value of the header.

    Header handler functions should return a dictionary of the variables
    they want to update in the calling scope.

    If the function does not exist, return an empty dictionary.
    '''
    # Replace header '-' with '_'.
    header_name = header['name'].replace('-', '_')

    # Check for a function in the current scope of the name of the header.
    # If the function exists, call it with the value of the header.

    try:
        result = globals()[header_name](header['value'], calling_scope)
        print(f"Function result: {result}")
        return result
    except KeyError as ke:
        print(f"Function '{header_name}' does not exist. {ke}")
    except TypeError as te:
        print(f"Argument mismatch when calling '{header_name}': {te}")
        raise

    return {}

def lambda_handler(event, context):
    print("Received event: " + json.dumps(event, indent=2))

    # Get the object from the event and show its content type
    try:
        if event['Records'][0]['eventSource'] != 'aws:ses':
            # STOP_RULE will continue on te the next rule which should be 
            # reject.
            
            return 'STOP_RULE'
        
        event_headers = event['Records'][0]['ses']['mail']['headers']

        # Check headers for X-SES-Spam-Verdict and X-SES-Virus-Verdict

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

            header_handler_result = invoke_header_handler(header, locals())
            if header_handler_result:
                locals().update(header_handler_result)

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
    
    except StopRuleException as sre:
        print(sre)
        return 'STOP_RULE'
    
    except StopRuleSetException as srse:
        print(srse)
        return 'STOP_RULE_SET'
    
    except Exception as e:
        print(e)
        raise
