# Mock GCP/Vertex AI initialization and auth for local tests
import sys
from unittest.mock import MagicMock, AsyncMock

# Mock google.auth.default before imports occur
import google.auth
from google.auth import credentials

mock_creds = MagicMock(spec=credentials.Credentials)
# Provide required string attributes for auth headers
mock_creds.token = "fake-token"
mock_creds.refresh = MagicMock()
mock_creds.quota_project_id = "dummy-project"
mock_creds.project_id = "dummy-project"
google.auth.default = MagicMock(return_value=(mock_creds, "dummy-project"))

# Mock vertexai
import vertexai
vertexai.init = MagicMock()

# Mock google.cloud.logging
import google.cloud.logging
google.cloud.logging.Client = MagicMock()

# Mock google.genai GenerativeModel to avoid real network calls
import google.genai as genai
from google.genai import types as genai_types

mock_model = MagicMock()

async def dummy_event_generator(*args, **kwargs):
    # Simulate a single streaming event with text content
    content = genai_types.Content(
        role="model",
        parts=[genai_types.Part.from_text(text="Mock LLM response")],
    )
    event = MagicMock()
    event.content = content
    yield event

mock_model.generate_content = AsyncMock(side_effect=dummy_event_generator)
genai.GenerativeModel = MagicMock(return_value=mock_model)

# Ensure any imports of google.genai after this use the mock
