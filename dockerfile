# Use the official AWS Lambda Python 3.9 base image
FROM public.ecr.aws/lambda/python:3.9

# Copy the function code and requirements.txt into the container
COPY lambda_function.py ${LAMBDA_TASK_ROOT}/
COPY requirements.txt ${LAMBDA_TASK_ROOT}/

# Install packages from both public and private indexes
RUN pip install --no-cache-dir -r requirements.txt

# Command to run the Lambda function
CMD ["lambda_function.lambda_handler"]

