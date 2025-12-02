from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
from stig_data_model import StigDataModel
import os
from urllib.parse import parse_qs
from dotenv import load_dotenv
load_dotenv()

app = FastAPI(title="STIG RAG API")

endpoint_url = os.getenv("AWS_S3_ENDPOINT")

access_key_id = os.getenv("AWS_ACCESS_KEY_ID")

secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY")

bucket = os.getenv("AWS_S3_BUCKET")

db_name = os.getenv("DB_NAME")

table_name = os.getenv("TABLE_NAME")

data_model = StigDataModel(endpoint_url=endpoint_url,
                     access_key_id=access_key_id,
                     secret_access_key=secret_access_key,
                     bucket=bucket,
                     db_name=db_name,
                     table_name=table_name)

# Query documents by logs
@app.post("/stigs/query", response_class=PlainTextResponse)
async def find_documents_by_logs(request: Request):
    """
    Handles querying documents based on provided logs.

    Returns:
        The documents matching the query, represented as a plain text response.
    """
    query_string = request.scope["query_string"].decode("utf-8")

    parsed_query = parse_qs(query_string)

    logs = parsed_query.get("logs", [""])[0]

    return PlainTextResponse(content=data_model.run_query({
        "prompt": logs
    }))
