import time
import schedule
import boto3
import pandas as pd
import json
import numpy as np

def load_preprocessed_data(file_path):
    # Load the preprocessed and scaled data
    return pd.read_json(file_path)

def invoke_sagemaker_endpoint(endpoint_name, data):
    # Call the SageMaker endpoint to make predictions
    client = boto3.client('sagemaker-runtime')

    # Convert the data to a simple JSON array without any metadata
    payload = json.dumps(data.values.tolist())

    # Invoke the endpoint
    response = client.invoke_endpoint(
        EndpointName=endpoint_name,
        ContentType='application/json', 
        Body=payload
    )

    # Parse the response
    result = response['Body'].read().decode('utf-8')
    predictions = json.loads(result) 
    return np.array(predictions)

def save_predictions(predictions, output_file):
    # Save the predictions to a CSV file
    pd.DataFrame(predictions, columns=['Prediction']).to_csv(output_file, index=False)

if __name__ == "__main__":
    # Paths to the necessary files
    preprocessed_data_file = 'data_dump/flow_logs.json'
    output_predictions_file = 'data_dump/predictions.json'
    sagemaker_endpoint_name = 'sagemaker-scikit-learn-2024-08-01-18-54-02-067'
    
    # Step 1: Load the preprocessed data
    data = load_preprocessed_data(preprocessed_data_file)
    
    # Step 2: Invoke the SageMaker endpoint
    predictions = invoke_sagemaker_endpoint(sagemaker_endpoint_name, data)
    
    # Step 3: Save the predictions
    save_predictions(predictions, output_predictions_file)
    
    print(f"Predictions saved to {output_predictions_file}")
