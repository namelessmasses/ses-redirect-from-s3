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
sns = boto3.client('sns')

class StopRuleException(Exception):
    def __str__(self):
        return f"StopRuleException: {self.args}"

class StopRuleSetException(Exception):
    def __str__(self):
        return f"StopRuleSetException: {self.args}"

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

    print(f"{dynamo_response}")

    item = dynamo_response.get('Item', None)
    print(f"{item=}")

    if not item:
        return None

    for k, v in item.items():
        print(f"get_python_from_dynamo: {k}: {v}")

    return dynamo_to_python(item)

def get_rewrite_rules(key):
    # Treat 'key' as a complete to-address; <to>@<domain>.
    # If no rewrite rules can be found under that key, 
    # then query for the '@<domain>'.
    
    # If key contains friendly name, remove it.
    if '<' in key and '>' in key:
        key = re.search(r'<(.*?)>', key).group(1)
    
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
    print(f"{raw_email=}")
    return raw_email

def onheader_X_s3_bucket_prefix(value, calling_locals):
    '''
    Extract the bucket and prefix from the header value.

    The header value is expected to be in the format 'bucket/prefix/'.
    '''
    (bucket, *prefix) = value.split('/')
    prefix = '/'.join(prefix)
    return {'bucket': bucket, 'prefix': prefix}

def onheader_Received(value, calling_locals):
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

def onheader_X_SES_Spam_Verdict(value, calling_locals):
    '''
    Throw StopRuleException if value is not 'PASS'.

    Stopping the rule should allow the following rule in the set to be executed.
    The following rule should be a reject rule for the same domain.
    '''
    print(f"X_SES_Spam_Verdict: {value=}")
    if value.upper() != 'PASS':
        raise StopRuleException(f"Spam verdict is {value}")

    return {}

def onheader_X_SES_Virus_Verdict(value, calling_locals):
    '''
    Throw StopRuleException if value is not 'PASS'.

    Stopping the rule should allow the following rule in the set to be executed.
    The following rule should be a reject rule for the same domain.
    '''
    print(f'X_SES_Virus_Verdict: {value=}')
    if value.upper() != 'PASS':
        raise StopRuleException(f"Virus verdict is {value}")

    return {}    

def onheader_reply_to(value, calling_locals):
    '''
    Add the 'reply_to' key to the calling_locals dictionary with the value of the header.
    '''
    calling_locals['reply_to'] = value
    return {}

def onheader_Reply_To(value, calling_locals):
    return onheader_reply_to(value, calling_locals)

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
    header_handler_name = f'onheader_{header_name}'

    try:
        return globals()[header_handler_name](header['value'], calling_scope)
    except KeyError as ke:
        print(f"Function '{header_handler_name}' does not exist. {ke}")
    except TypeError as te:
        print(f"Argument mismatch when calling '{header_handler_name}': {te}")
        raise

    return {}

def get_outbound_from(original_from, rewrite_rules):
        if rewrite_rules.rewrite_from == '$return_path':
            return rewrite_rules.return_path
        
        if rewrite_rules.rewrite_from.startswith('<original_from>@'):
            # Reformat original_from converting so that it can be placed before
            # @ in the rewrite_from.
            rewritten_from = original_from.replace('@', '_at_')

            # Ensure that rewritten_from removes any "Name <email>" format and is
            # just the email.
            if '<' in rewritten_from and '>' in rewritten_from:
                rewritten_from = re.search(r'<(.*?)>', rewritten_from).group(1)

            return 'no-receipt-' + rewrite_rules.rewrite_from.replace('<original_from>', rewritten_from)
        
        return rewrite_rules.rewrite_from

def lambda_handler(event, context):
    print('Received event (compact)', json.dumps(event, separators=(',', ':'), indent=None))
    print("Received event: " + json.dumps(event, separators=(',', ':'), indent=0))
    print("Received context: " + str(context))

    # Get the object from the event and show its content type
    try:
        if event['Records'][0]['eventSource'] != 'aws:ses':
            # STOP_RULE will continue on te the next rule which should be 
            # reject.
            
            return 'STOP_RULE'
        
        event_headers = event['Records'][0]['ses']['mail']['headers']
        handled_headers = {}
        for header in event_headers:
            print(f'{header=}')
            header_handler_result = invoke_header_handler(header, handled_headers)
            print(f'{header_handler_result=}')
            if header_handler_result:
                handled_headers.update(header_handler_result)

        bucket = handled_headers.get('bucket', None)
        prefix = handled_headers.get('prefix', None)
        object_name = handled_headers.get('object_name', None)
        if not bucket or not prefix:
            raise KeyError(f"Missing header X-s3-bucket-prefix: {bucket}, {prefix}")
        
        if not object_name:
            raise KeyError(f"Missing SMTP id in Received header")

        key = f'{prefix}{object_name}'

        print(f"{bucket=}, {key=}")

        raw_email = read_raw_from_s3(bucket, key)
        msg = email.message_from_string(raw_email)
        print(f"{msg=}")

        rewrite_rules = get_rewrite_rules(msg['To'])

        return_path = rewrite_rules.rewrite_return_path
        msg.replace_header('Return-Path', return_path) if 'Return-Path' in msg else msg.add_header('Return-Path', return_path)

        outbound_from = get_outbound_from(msg['From'], rewrite_rules)
        print(f"{outbound_from=}")
        
        # Headers to be tweaked for SES sending.

        # If msg has multiple 'DKIM-Signature' headers, remove all but the first.
        # TODO Workaround for SES not allowing multiple DKIM-Signature headers.
        # This is a temporary fix until SES supports multiple DKIM signatures.
        dkim_signatures = msg.get_all('DKIM-Signature', [])
        if len(dkim_signatures) > 1:
            print(f"Multiple DKIM-Signature headers found: {len(dkim_signatures)}. Removing all.")
            del msg['DKIM-Signature']
            msg.add_header('DKIM-Signature', dkim_signatures[-1])  # Keep the last one
            dkim_signatures = msg.get_all('DKIM-Signature', [])
            
        print(f"Remaining DKIM-Signature headers: {len(dkim_signatures)}")

        # Sender -> X-Mask-Original-Sender
        if 'Sender' in msg:
            original_sender = msg['Sender']
            msg.replace_header('Sender', outbound_from)
            msg.add_header('X-Mask-Original-Sender', original_sender)

        # Reply-To:
        #   - Remove the header from the message.
        #   - Use the value of the original reply-to: (handled_headers['reply_to']) 
        #     as the friendly name for outbound_from.
        if 'Reply-To' in msg:
            del msg['Reply-To']
            outbound_from = f'"{handled_headers["reply_to"]}" <{outbound_from}>'
        elif 'reply-to' in msg:
            del msg['reply-to']
            outbound_from = f'"{handled_headers["reply_to"]}" <{outbound_from}>'
        
        print(f"Final: {outbound_from=}")
        print(f'{msg.as_string()=}')
        
        response = ses.send_email(
            FromEmailAddress = outbound_from,
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

        return dict(disposition='CONTINUE')
    
    except StopRuleException as sre:
        print(f'{sre=}')
        return dict(disposition='STOP_RULE')
    
    except StopRuleSetException as srse:
        print(f'{srse=}')
        return dict(disposition='STOP_RULE_SET')
    
    except Exception as e:
        print(f'{e=}')
        raise
