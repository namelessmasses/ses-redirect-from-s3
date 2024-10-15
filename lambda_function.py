import json
import urllib.parse
import boto3
import email

print('Loading function')

s3 = boto3.client('s3')
ses = boto3.client('sesv2')
dynamodb = boto3.resource('dynamodb');
ses_rewrite = dynamodb.Table('ses_redirect_rewrite_rules')
deserializer = boto3.dynamodb.types.TypeDeserializer()

def dynamo_to_python(dynamodb_response : dict) -> dict:
    return {
        k: deserializer.deserialize(v)
        for k, v in dynamodb_response.items()
    }

def get_rewrite_rules(key):
    # Treat 'key' as a complete to-address; <to>@<domain>.
    # If no rewrite rules can be found under that key, 
    # then query for the '@<domain>'.
    
    dynamo_response = ses_rewrite.query(
        KeyConditionExpression = boto3.dynamodb.conditions.Key('to_address').eq(key)
    )

    response = dynamo_to_python(dynamo_response)
    if response.Count > 0:
        return response

    # Try @<domain> for rewrite rules.

    key = '@' + key.split('@')[1]
    dynamo_response = ses_rewrite.query(
        KeyConditionExpression = boto3.dynamodb.conditions.Key('to_address').eq(key)
    )

    response = dynamo_to_python(dynamo_response)
    if response.Count > 0:
        return response

    raise KeyError()

def lambda_handler(event, context):
    print("Received event: " + json.dumps(event, indent=2))

    # Get the object from the event and show its content type
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = urllib.parse.unquote_plus(event['Records'][0]['s3']['object']['key'], encoding='utf-8')
    try:
        response = s3.get_object(Bucket=bucket, Key=key)
        print("CONTENT TYPE: " + response['ContentType'])

        raw_email = response['Body'].read().decode('utf-8')
        print("S3 Email: " + raw_email)
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
    except Exception as e:
        print(e)
        raise e
