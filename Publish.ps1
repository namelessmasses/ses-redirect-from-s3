7z u -spf2 -r -tzip code.zip src/lambda_function.py
# Create a new version for rollback
aws lambda publish-version --function-name ses-redirect-from-s3 --no-cli-pager
# Publish new code
aws lambda update-function-code --function-name ses-redirect-from-s3 --zip-file fileb://./code.zip --no-cli-pager
