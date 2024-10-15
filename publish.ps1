git archive --output code.zip HEAD
aws lambda update-function-code --function-name ses-redirect-from-s3 --zip-file fileb://./code.zip
aws lambda publish-version --function-name ses-redirect-from-s3
