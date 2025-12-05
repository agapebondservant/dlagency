from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from stig_data_model import StigDataModel
import os
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
@app.post("/stig-logs")
async def find_documents_by_logs(logs: str):
    """
    Handles querying documents based on provided logs.

    Returns:
        The documents matching the query, represented as a plain text response.
    """
    print(logs)

    return PlainTextResponse(content=data_model.run_query({
        "prompt": logs
    }))

@app.patch("/stigs/{rule_id}")
async def update_logs_by_rule_id(rule_id: str, logs: str):
    """
    Updates logs associated with the given rule ID.

    Args:
        rule_id: The identifier of the rule whose logs need to be updated.
        logs: The updated logs to be associated with the specified rule.
    Returns:
        Text response containing the result of the log update operation.
    """
    response = data_model.update_logs_by_rule_id(
        rule_id, logs)

    if not response:
        raise HTTPException(status_code=404, detail=f"Rule ID {rule_id} "
                                                    f"could not be updated.")

    return PlainTextResponse(content=data_model.update_logs_by_rule_id(
        rule_id, logs)
    )