import boto3
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
from langchain_community.embeddings import HuggingFaceEmbeddings, SentenceTransformerEmbeddings
import numpy as np
import traceback
# import nest_asyncio
# nest_asyncio.apply()
from dotenv import load_dotenv
load_dotenv()

class StigDataModel:
    """
    Handles connections to a LanceDB database and initializes an embedding model
    for storing and retrieving data in an S3 bucket effectively.

    Instance Variables:
        endpoint_url: AWS S3 endpoint URL used for connecting to the service.
        access_key_id: AWS access key ID used for authentication.
        secret_access_key: AWS secret access key used for authentication.
        bucket: Name of the AWS S3 bucket where the database resides.
        db_name: Name of the LanceDB database.
        table_name: Name of the LanceDB table where data is stored.
        db: The connected LanceDB database instance.
        embedding_model: The initialized embedding model instance.
    """
    def __init__(self,
                 endpoint_url: str,
                 access_key_id: str,
                 secret_access_key: str,
                 bucket: str,
                 db_name: str,
                 table_name: str,
                 embedding_model_name: str = "all-MiniLM-L6-v2"):
        
        self.endpoint_url = endpoint_url
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self.bucket = bucket
        self.db_name = db_name
        self.table_name = table_name
        self.db = self.initialize_connection()
        self.embedding_model_name = embedding_model_name
        self.embedding_model = self.initialize_embedding_model()

    def initialize_connection(self):
        """
        Initializes and establishes a connection to a LanceDB database using the specified
        parameters for the database endpoint and credentials.

        Returns:
            A connected LanceDB database object.
        """
        db = lancedb.connect(f"s3://{self.bucket}/{self.db_name}",
             storage_options={
                 "endpoint_url": self.endpoint_url,
                 "aws_access_key_id": self.access_key_id,
                 "aws_secret_access_key": self.secret_access_key,
                 "s3_force_path_style": "true",
                 "allow_http": "true",
             }
        )

        print(f"Connected to database, db=s3://{self.bucket}/{self.db_name}")

        print(db.table_names())

        return db

    def initialize_embedding_model(self):
        """
        Initializes and returns an embedding model instance configured with
        the HuggingFaceEmbeddings class and specified model settings.

        Returns:
            An initialized HuggingFaceEmbeddings object.
        """
        return HuggingFaceEmbeddings(model_name=self.embedding_model_name,
                                     model_kwargs={"trust_remote_code":True})

    def find_documents_by_logs(self, logs: str) -> str :
        """
        Search and retrieve documents from a database table based on provided logs and query
        vector embedding. Leverages a hybrid query mechanism and a custom reranker to refine
        search results before returning a limited selection of matching documents.

        Args:
            logs: The search query or logs to use for retrieving relevant
        documents.
        Returns:
            A list of dictionaries containing fields of the retrieved
        documents.
        """
        try:

            if not logs:
                print("No logs provided, returning empty results.")

                return ""

            print(f"Connecting to table={self.table_name}...")

            table = self.db.open_table(self.table_name)

            query_vector = np.array(self.embedding_model.embed_query(logs),
                                    dtype=np.float32).tolist()

            reranker = LinearCombinationReranker()

            print("Running query...")

            results = table.search(query_type="hybrid",
                                   vector_column_name="vector").vector(
                query_vector).text(logs).rerank(reranker=reranker).select(
                ["text", "log_entry"]).limit(3).to_list()

            print("=============RESULTS===============", results)

            return results
        except Exception as e:
            print(f"Error searching documents: {e}")
            traceback.print_exc()
            return []


    def run_query(self, body: dict) -> str:
        """
        Executes a query based on provided input.

        Args:
            body: A dictionary containing the necessary keys and values for the
        query.
        Returns:
            A string containing the formatted query results.
        """
        try:
            if not body or "prompt" not in body:
                return "ERROR: Missing required 'prompt' parameter"

            prompt = body.get("prompt")

            retrieved_docs = self.find_documents_by_logs(prompt)

            print(retrieved_docs)

            if not retrieved_docs:
                return "ERROR: No relevant documents found"

            context = "\n\n".join([f"""
                ### Sample Logs:
                {doc['log_entry']}
                
                ### Violated STIG control:\n{doc['text']}""" for doc in
                                   retrieved_docs])

            return context
        except Exception as e:
            print(f"Error running query: {e}")
            traceback.print_exc()