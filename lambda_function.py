from custom_encoder import CustomEncoder
import boto3
import json
import logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)
import botocore.exceptions 

dynamodbTableName = 'product_inventory'
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(dynamodbTableName)

getMethod = 'GET'
postMethod = 'POST'
patchMethod = 'PATCH'
deleteMethod = 'DELETE'
healthPath = '/health'
productPath = '/product'
productsPath = '/products'


def lambda_handler(event, context):
    logger.info(event)
    httpMethod = event['httpMethod']
    path = event['path']
 
    if httpMethod == getMethod and path == healthPath:
        response = buildResponse(200)
    elif httpMethod == getMethod and path == productPath:
        response = getProduct(event['queryStringParameters']['productId'])

    elif httpMethod == getMethod and path == productsPath:
        print(productsPath)
        response = getProducts()
    elif httpMethod == postMethod and path == productPath:

        response = saveProduct(json.loads(event['body']))
    elif httpMethod == patchMethod and path == productPath:
        requestBody = json.loads(event['body'])
        response = modifyProduct(
            requestBody['productId'], requestBody['updateKey'], requestBody['updateValue'])
    elif httpMethod == deleteMethod and path == productPath:
        requestBody = json.loads(event['body'])
        response = delete(requestBody['productId'])
    else:
        response = buildResponse(404, 'Not Found')
    return response


def getProduct(productId):
    try:
        response = table.get_item(
            key={
                'productId': productId
            }
        )
        if 'Item' in response:
            return buildResponse(200, response['Item'])
        else:
            return buildResponse(404, {'Message': 'ProductId: %s not found' % productId})
    except:
        logger.exception("Error in getting single product")


def saveProduct(requestBody):
    try:
        table.put_item(Item=requestBody)
        body = {
            'Operation': 'SAVE',
            'Message': 'SUCCESS',
            'Item': requestBody
        }
        return buildResponse(200, body)
    
    except botocore.exceptions.ClientError as e:
        # Handle the exception
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        logger.error(f"Error: {error_code} - {error_message}")

def modifyProduct(productId, updateKey, updateValue):
    try:
        response = table.update_item(
            Key={
                'productId': productId
            },
            UpdateExpression=f'set {updateKey} = :value', 
            ExpressionAttributeValues={
                ':value': updateValue 
            },
            ReturnValues='UPDATED_NEW'
        )

        body = {
            'Operation': 'UPDATE',
            'Message': 'SUCCESS',
            'UpdatedAttributes': response
        }
        return buildResponse(200, body)
    except:
        logger.exception("Error in modifying the product")



def delete(productId):
    try:
        response = table.delete_item(
            Key={
                'productId': productId
            },
            ReturnValues='ALL_OLD'  # Use 'ALL_OLD' to return the deleted item
        )

        body = {
            'Operation': 'DELETE',
            'Message': 'SUCCESS',
            'deletedItem': response['Attributes'] if 'Attributes' in response else {}
        }
        return buildResponse(200, body)
    except:
        logger.exception("Error in deleting the product")


def getProducts():
    try:
        response = table.scan()
        result = response['Items']

        while 'LastEvaluatedKey' in response:
            response = table.scan(
                ExclusiveStartKey=response['LastEvaluatedKey'])
            result.extend(response['Items'])

        body = {
            'products': result
        }

        return buildResponse(200, body)
    except botocore.exceptions.ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        logger.error(f"Error: {error_code} - {error_message}")


def buildResponse(statusCode, body=None):
    response = {
        'statusCode': statusCode,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        }
    }
    if body is not None:
        response['body'] = json.dumps(body, cls=CustomEncoder)
    return response
