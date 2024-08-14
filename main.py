import time
import schedule
import os
import boto3
import pandas as pd
import json
import numpy as np
from data_collection.collection import mainCollection, collect_vpc_logs, parse_log
from data_collection.preprocessing import mainPreprocessing, infer_service_from_port, decode_tcp_flags, convert_to_high_level_flag, preprocess_flow_logs, save_preprocessed_data

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

def send_sns_alert(message, sns_topic_arn):
    sns_client = boto3.client('sns')
    sns_client.publish(
        TopicArn=sns_topic_arn,
        Message=message,
        Subject='AWS Anomaly Detection Alert'
    )
    print(f"Alert sent: {message}")

def main_predict_pipeline():

    mainCollection()
    mainPreprocessing()

    # Paths to the necessary files
    preprocessed_data_file = 'data_dump/flow_logs.json'
    output_predictions_file = 'predictions/predictions.csv'
    sagemaker_endpoint_name = 'sagemaker-scikit-learn-2024-08-01-18-54-02-067'

    
    # Step 1: Load the preprocessed data
    data = load_preprocessed_data(preprocessed_data_file)
    
    # Step 2: Invoke the SageMaker endpoint
    predictions = invoke_sagemaker_endpoint(sagemaker_endpoint_name, data)
    
    # Step 3: Save the predictions
    save_predictions(predictions, output_predictions_file)
    print(f"Predictions saved to {output_predictions_file}")

    # Step 4: Send SNS alert
    if np.any(predictions > 0):  # Adjust condition based on your definition of a positive prediction
        message = "Anomaly detected! Check the predictions for details."
        sns_topic_arn = 'arn:aws:sns:us-east-2:851725192656:AnomalyDetection'  
        send_sns_alert(message, sns_topic_arn)
    
    print(f"Predictions saved to {output_predictions_file}")

    if os.path.exists("data_dump/flow_logs.json") or os.path.exists("data_dump/vpc_logs.json"):
        os.remove("data_dump/flow_logs.json")
        os.remove("data_dump/vpc_logs.json")


# Schedule the task to run every minute
schedule.every(1).minutes.do(main_predict_pipeline)

if __name__ == "__main__":

    # Run the scheduled task indefinitely
    while True:
        schedule.run_pending()
        time.sleep(1)
