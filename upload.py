import boto3
import sagemaker

#Initialize SageMaker session
sagemaker_session = sagemaker.Session()

default_bucket = sagemaker_session.default_bucket()

s3 = boto3.client('s3')
model_file = 'vigil_model.tar.gz'
s3.upload_file(model_file, default_bucket, model_file)