import sagemaker
from sagemaker.sklearn import SKLearnModel

role = 'arn:aws:iam::851725192656:role/service-role/AmazonSageMaker-ExecutionRole-20240714T231690'

# Initialize SageMaker session
sagemaker_session = sagemaker.Session()

# Get default s3 bucket
default_bucket = sagemaker_session.default_bucket()
model_file = 'models/vigil_mode.tar.gz'

# Create SageMaker model
model = SKLearnModel(
    model_data=f's3://{default_bucket}/{model_file}',
    role=role,
    entry_point='packages/inference.py',
    framework_version='0.23-1',
    py_version='py3'
)

# Deploy model to endpoint
predictor = model.deploy(
    initial_instance_count=1,
    instance_type='ml.t2.medium'
)

print(f'Model deployed to endpoint: {predictor.endpoint_name}')

# Delete endpoint after usage

"""
predictor.delete_endpoint()
print(f'Endpoint {predictor.endpoint_name} deleted')
"""