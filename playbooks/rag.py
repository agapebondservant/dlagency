#!/usr/bin/env python
# coding: utf-8

# <div style="background-color: #ADD8E6; border: 1px solid gray; padding: 3px">
#         <h3>Data Generation Workflow</h3>
#         <li><b>Data Extraction</b>: Extracts data from markdown files using LangChain.</li>
#         <li><b>Data Generation</b>: Generates data records using sdg_hub.</li>
#         <li><b>Data Uploads</b>: Uploads generated data to MinIO.</li>
#         <li><b>Data Population</b>: Builds LanceDB store.</li>
# </div>

# In[25]:


###################################################################################################
# Imports
###################################################################################################
import boto3
import os
from langchain_openai import ChatOpenAI, OpenAI
from langchain_community.vectorstores import LanceDB
from langchain_community.embeddings import OpenAIEmbeddings
from langchain_community.document_loaders import TextLoader
from langchain_community.graph_vectorstores import GraphVectorStoreRetriever
from langchain_core.documents import Document
from lancedb.rerankers import LinearCombinationReranker
from langchain_openai import OpenAIEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter, MarkdownHeaderTextSplitter
from langchain.docstore.document import Document
from langchain_core.prompts import ChatPromptTemplate, SystemMessagePromptTemplate, HumanMessagePromptTemplate
import lancedb
from huggingface_hub import snapshot_download
from langchain_community.embeddings import HuggingFaceEmbeddings, SentenceTransformerEmbeddings
from transformers import AutoTokenizer
from enum import Enum
import traceback
import numpy as np
import re
import uuid
import pandas as pd
import pprint
from datasets import Dataset
from sdg_hub.core.flow import FlowRegistry, Flow
from flow_extensions import CustomDeleteColumnsBlock
import nest_asyncio
import litellm
import json
from tabulate import tabulate
nest_asyncio.apply()
from dotenv import load_dotenv
load_dotenv()


# In[2]:


###################################################################################################
# Instance variables
###################################################################################################
endpoint_url = os.getenv('AWS_S3_ENDPOINT')
access_key_id = os.getenv('AWS_ACCESS_KEY_ID')
secret_access_key = os.getenv('AWS_SECRET_ACCESS_KEY')
bucket = os.getenv("AWS_S3_BUCKET")
target_path = "data"

embedding_model = HuggingFaceEmbeddings(
    model_name="all-MiniLM-L6-v2", 
    model_kwargs={"trust_remote_code":True}
)

db = lancedb.connect(f"s3://data/lancedb-dla",
    storage_options={
        "endpoint_url": endpoint_url,
        "aws_access_key_id": access_key_id,
        "aws_secret_access_key": secret_access_key,
        "s3_force_path_style": "true",
        "allow_http": "true",
    }
)

minio = boto3.client(
    's3',
    endpoint_url=endpoint_url,
    aws_access_key_id=access_key_id,
    aws_secret_access_key=secret_access_key,
    config=boto3.session.Config(signature_version='s3v4')
)


# In[3]:


###################################################################################################
# Generate raw data
###################################################################################################

def build_raw_dataset(target_dir, suffix=".md", prefix=""):
    """
    Extracts STIG data from markdown files.
    """
    try:

        data, current_group_content = [], None

        files = os.listdir(target_dir)

        files = [f for f in files if f.endswith(".md") and f.startswith(prefix)]

        for file in files:
            
            filecontent = None
            
            with open(f"{target_dir}/{file}", mode="r") as f: 
                
                filecontent = f.read()
                
            headers_to_split = [("##", "Group"), ("###", "Rule")]
            
            text_splitter = MarkdownHeaderTextSplitter(headers_to_split, strip_headers=False)
            
            splits = text_splitter.split_text(filecontent)
    
            for split in splits:
    
                if "Group" in split.metadata and "Rule" not in split.metadata:
    
                    current_group_content = split.page_content
                
                if "Group" in split.metadata and "Rule" in split.metadata:
                
                    content = f"""{current_group_content.strip()}{split.page_content.strip()}"""
                    
                    data.append({"id": str(uuid.uuid4()),
                                "text": content,
                                })   

        # pprint.pprint(data)
    
        df = pd.DataFrame(data)

        ds = Dataset.from_pandas(df)
        
        return ds
        
    except Exception as e:
        print(f"Error extracting data from {target_dir}: {e}")
        
        traceback.print_exc() 


# In[4]:


###################################################################################################
# Generate synthetic data
###################################################################################################
def build_synthetic_dataset(ds):
    from datasets import load_dataset, DatasetDict
    
    flow_path = "flows/rag_knowledge_generation/flow.yaml"
    
    flow = Flow.from_yaml(flow_path)
    
    flow.set_model_config(
        model=os.getenv("LLM_ID"),
        
        api_key=os.getenv('LLM_TOKEN'),
        
        api_base=os.getenv('LLM_API_BASE'),
        
        temperature=0.1,
    )
        
    dataset = flow.generate(ds, max_concurrency=100)
    
    dataset.to_json(f"{target_path}/stig_data.jsonl")

    dataset.to_parquet(f"{target_path}/stig_data.parquet")


# In[5]:


###################################################################################################
# Upload data to LanceDB
###################################################################################################
# Migrate Local Search tables

def upload_to_lancedb(parquet_dir, connection):
    """
    Uploads the parquet file(s) in the provided directory to the specified lancedb database connection.
    """
    print("Migrating data to LanceDB...")
    
    try:
        for file_path in os.listdir(f"{target_path}"):
            
            if file_path.endswith(".parquet"):
        
                try:
            
                    full_path = os.path.join(target_path, file_path)
        
                    df = pd.read_parquet(full_path)

                    text_embeddings = embedding_model.embed_documents(df['text'].tolist())

                    log_embeddings = embedding_model.embed_documents(df['log_entry'].tolist())
                    
                    df['vector'] = [np.array(e, dtype=np.float32).tolist() for e in text_embeddings]

                    df['logs_vector'] = [np.array(e, dtype=np.float32).tolist() for e in log_embeddings]
        
                    table_name = file_path.split(".", 1)[0]
        
                    table = connection.create_table(table_name, data=df)

                    table.create_fts_index("text")

                    table.create_fts_index("log_entry")

                    table.create_index(metric="cosine", vector_column_name="vector")

                    table.create_index(metric="cosine", vector_column_name="logs_vector")
        
                    print(f"{table_name} migrated.")
        
                except Exception as e:
                    
                    print(f"Error uploading data from {full_path}: {e}")    
            
        print("Migration complete.")
        
    except Exception as e:
        
        print(f"Error uploading data to LanceDB: {e}")

        traceback.print_exc()


# ## Run data generation pipeline
# Run the pipeline!

# In[6]:


# os.makedirs("data", exist_ok=True)

# ds = build_raw_dataset("markdown", prefix="U_RH")

# build_synthetic_dataset(ds)

upload_to_lancedb(target_path, db)

print(f"Transformation complete.")


# In[56]:


###################################################################################################
# Test LanceDB Query
###################################################################################################
client = OpenAI(
    api_key=os.getenv("GRANITE_LLM_TOKEN"),
    
    base_url=os.getenv('GRANITE_LLM_BASE_URL'),
)

def retrieve_documents(logs: str):
    table = db.open_table("stig_data")
    
    # query_vector = embedding_model.embed_query(logs).astype(np.float32).tolist()

    query_vector = np.array(embedding_model.embed_query(logs), dtype=np.float32).tolist()

    reranker = LinearCombinationReranker() 
    
    results = table.search(query_type="hybrid",vector_column_name="vector").vector(query_vector).text(logs).rerank(reranker=reranker).select(["text", "log_entry"]).limit(3).to_list()

    return results
    

def run_query(body: dict) -> dict:
    prompt = body.get("prompt")
    
    max_tokens = body.get("max_tokens", 8192)
    
    temperature = body.get("temperature", 0.1)
    
    top_p = body.get("top_p", 1)
    
    n = body.get("n", 1)
    
    retrieved_docs = retrieve_documents(prompt)

    # print(json.dumps(retrieved_docs, indent=4))
    
    context = "\n\n".join([f"### Sample Logs (Relevance Score={doc['_relevance_score']}):\n{doc['log_entry']}\n\n### Violated STIG control:\n{doc['text']}" for doc in retrieved_docs])
    
    print(context)

    # 2. Construct the prompt with context
    user_message = f"""
    You are a helpful assistant with expertise in system engineering and cybersecurity. 
    Provide an analysis of the following RHEL logs and system configuration against the relevant STIG compliance requirements. 
    Identify specific violations and recommend a prioritized course of action to remediate each non-compliant finding, 
    including estimated effort and impact.
    Also identify the priority level of the violation based on the STIG category.
    Where appropriate, use the context provided here:
    {context}
    
    Logs: 
    {prompt}
    
    Analysis:
    """

    # 3. Send the request to the local LLM using the OpenAI client
    try:
        response = litellm.completion(
            model=f"hosted_vllm/{os.getenv('GRANITE_LLM_ID')}",
            messages=[
                {"role": "user", "content": user_message}
            ],
            temperature=temperature,
            max_tokens=max_tokens,
            top_p=top_p,
            n=n,
            api_key=os.getenv("GRANITE_LLM_TOKEN"),
            base_url=os.getenv('GRANITE_LLM_BASE_URL'),
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Error communicating with local LLM: {e}"


# In[57]:


###################################################################################################
# Sample Logs
###################################################################################################
prompt1 = """
× httpd.service - The Apache HTTP Server
     Loaded: loaded (/usr/lib/systemd/system/httpd.service; disabled; preset: disabled)
     Active: failed (Result: exit-code) since Tue 2025-04-08 15:56:15 UTC; 1h 11min ago
   Duration: 1min 9.506s
       Docs: man:httpd.service(8)
    Process: 4099 ExecStart=/usr/sbin/httpd $OPTIONS -DFOREGROUND (code=exited, status=1/FAILURE)
   Main PID: 4099 (code=exited, status=1/FAILURE)
     Status: "Reading configuration..."
        CPU: 58ms

Apr 08 15:56:15 node1.example.com systemd[1]: Starting The Apache HTTP Server...
Apr 08 15:56:15 node1.example.com httpd[4099]: AH00526: Syntax error on line 35 of /etc/httpd/conf/httpd.conf:
Apr 08 15:56:15 node1.example.com httpd[4099]: Invalid command 'InvalidDirectiveHere', perhaps misspelled or defined by a module not included in the server configuration
Apr 08 15:56:15 node1.example.com systemd[1]: httpd.service: Main process exited, code=exited, status=1/FAILURE
Apr 08 15:56:15 node1.example.com systemd[1]: httpd.service: Failed with result 'exit-code'.
Apr 08 15:56:15 node1.example.com systemd[1]: Failed to start The Apache HTTP Server.
"""


# In[58]:


run_query({
    "prompt": prompt1
})


# In[24]:


import json


# In[11]:





# In[ ]:





# In[ ]:




