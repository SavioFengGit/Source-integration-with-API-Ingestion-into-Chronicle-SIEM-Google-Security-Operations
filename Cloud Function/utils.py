"""Utility functions required for ingestion scripts."""

import datetime
import json
import os
import sys
from typing import Dict, Any
from google.cloud import secretmanager

def now():
  """
  Gets the current time in ISO 8601 format with Zulu timezone.

  Returns:
      str: The current time in ISO 8601 format with Zulu timezone.
  """
  current_time = datetime.datetime.now()
  formatted_time = current_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
  return formatted_time
  
def get_value_from_secret_manager(resource_path: str) -> str:
  """Retrieve the value of the secret from the Google Cloud Secret Manager.

  Args:
    resource_path (str): Path of the secret with version included. Ex.:
      "projects/<project_id>/secrets/<secret_name>/versions/1",
      "projects/<project_id>/secrets/<secret_name>/versions/latest"

  Returns:
    str: Payload for secret.
  """
  # Create the Secret Manager client.
  client = secretmanager.SecretManagerServiceClient()

  # Access the secret version.
  response = client.access_secret_version(name=resource_path)
  return response.payload.data.decode("UTF-8")


def get_env_var(
    name: str,
    required: bool = True,
    default: Any = None,
    is_secret: bool = False,
) -> Any:
  """Gets an environment variable.

  Args:
    name (str): Name of the environment variable.
    required (Optional[bool]): Script will exit with RuntimeError if this is
      True and variable is not set. Defaults to True.
    default (Optional[Any]): Default value to return in case the env variable is
      not set. Defaults to None.
    is_secret (bool): Script will get data from Google Cloud Secret Manager in
      case it is set to true.

  Returns:
    Any: Value of the environment variable.

  Raises:
    RuntimeError: Raises when required name is not in environment variable.
  """
  if name not in os.environ and required:
    raise RuntimeError(f"Environment variable {name} is required.")
  if is_secret:
    return get_value_from_secret_manager(os.environ[name])
  if name not in os.environ or (name in os.environ and
                                not os.environ[name].strip()):
    return default
  return os.environ[name]

def instance_region(region):
  """
  Retrieves the URL of the Malachite ingestion endpoint for the specified region.

  Args:
      region (str): The Malachite region.

  Returns:
      str: The URL of the Malachite ingestion endpoint for the specified region.

  Raises:
      ValueError: If the specified region is invalid.
  """

  REGIONS = {
      "europe": "https://europe-malachiteingestion-pa.googleapis.com",
      "singapore": "https://asia-southeast1-malachiteingestion-pa.googleapis.com",
      "us": "https://malachiteingestion-pa.googleapis.com",
      "london": "https://europe-west2-malachiteingestion-pa.googleapis.com",
      "sydney": "https://australia-southeast1-malachiteingestion-pa.googleapis.com",
      "telaviv": "https://me-west1-malachiteingestion-pa.googleapis.com",
      "frankfurt": "https://europe-west3-malachiteingestion-pa.googleapis.com",
      "zurich": "https://europe-west6-malachiteingestion-pa.googleapis.com"
  }
  if region not in REGIONS:
      raise ValueError("Invalid region. See https://cloud.google.com/terms/secops/data-residency.")
  return str(REGIONS[region])

def generate_epoch_timestamp(offset_minutes):
  """Generates an epoch timestamp.

  Args:
    offset_minutes: The number of minutes to offset the epoch timestamp.

  Returns:
    A float representing the number of seconds since the Unix epoch.
  """
  from time import time
  return int(time() - offset_minutes * 60)

def chunked_events(events, max_size):
    """Divide la lista events in sottoliste di dimensione massima."""
    chunk = []
    size = 0
    for event in events:
        event_size = sys.getsizeof(json.dumps(event))
        if size + event_size > max_size:
            yield chunk
            chunk = []
            size = 0
        chunk.append(event)
        size += event_size
    if chunk:
        yield chunk




def create_secret(
    project_id: str, secret_id: str
):
    """
    Create a new secret with the given name. A secret is a logical wrapper
    around a collection of secret versions. Secret versions hold the actual
    secret material.
    """


    # Create the Secret Manager client.
    client = secretmanager.SecretManagerServiceClient()

    # Build the resource name of the parent project.
    parent = f"projects/{project_id}"

    # Create the secret.
    response = client.create_secret(
        request={
            "parent": parent,
            "secret_id": secret_id,
            "secret": {"replication": {"automatic": {}}},
        }
    )
    # Print the new secret name.
    print(f"Created secret: {response.name}")

def update_secret(
    resource_path: str, text: str
):
    client = secretmanager.SecretManagerServiceClient()
    #text = text.encode('UTF-8')
    version = client.add_secret_version(
        request={"parent": resource_path, "payload": {"data": bytes(text, "UTF-8")}}
    )

    print(f"Updated secret {resource_path}!")