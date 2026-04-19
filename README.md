# SecOps MCP Server

Google Security Operations (SecOps) Model Context Protocol (MCP) server.

## How to Run Locally

1. Install dependencies:
   ```bash
   uv sync
   ```
2. Set environment variables (create a `.env` file):
   ```env
   CHRONICLE_PROJECT_ID=your_project_id
   CHRONICLE_CUSTOMER_ID=your_customer_id
   CHRONICLE_REGION=your_region
   ```
3. Run the server:
   ```bash
   uv run server.py
   ```

## How to Deploy to Cloud Run

For a detailed interactive guide, refer to the Jupyter notebook: [deploy_guide.ipynb](./deploy_guide.ipynb).

Quick summary of the command:
```bash
gcloud run deploy secops-mcp \
  --source . \
  --region us-central1 \
  --no-allow-unauthenticated \
  --project your_project_id
```
