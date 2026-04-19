# Copyright 2025 Google LLC
# Licensed under the Apache License, Version 2.0.
"""Google Security Operations MCP server."""

import logging
import os
import sys
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from utils import get_chronicle_client

load_dotenv()

server = FastMCP(
    "Google Security Operations MCP server",
    stateless_http=True,
    host="0.0.0.0",
    port=int(os.getenv("PORT", "9000"))
)

# Configure logging to stdout so we can see errors in Cloud Logging
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logger = logging.getLogger("secops-mcp")



from tools import *

def main() -> None:
    server.run(transport="streamable-http")

if __name__ == "__main__":
    main()
