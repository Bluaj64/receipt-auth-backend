import json


def lambda_handler(event, context):
    print("EVENT:", json.dumps(event))

    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json",
        },
        "body": json.dumps({
            "message": "Auth Lambda is working",
            "route": event.get("rawPath"),
        }),
    }