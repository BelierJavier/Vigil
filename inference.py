import joblib
import os
import json
import numpy as np

def model_fn(model_dir):
    model_path = os.path.join(model_dir, 'vigil_model.pkl')
    print(f'Loading model from {model_path}')
    model = joblib.load(model_path)
    return model

def input_fn(request_body, request_content_type):
    print(f'Received request with content type: {request_content_type}')
    if request_content_type == 'application/json':
        input_data = json.loads(request_body)
        return np.array(input_data)
    else:
        raise ValueError(f'Unsupported content type: {request_content_type}')

def predict_fn(input_data, model):
    print(f'Making predictions on input data: {input_data}')
    prediction = model.predict(input_data)
    return prediction.tolist()

def output_fn(prediction, response_content_type):
    print(f'Formatting prediction output: {prediction}')
    return json.dumps(prediction)