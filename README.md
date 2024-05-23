# Source-integration-(CTM360)-with-API-Ingestion-into-Chronicle-SIEM-Google-Security-Operations
In this repository I will show you how to integrate a source on the chronicle siem through the ingestion api. We will ingest in this case some IoC (entities). Take the CTM360 Threat intelligence source as an example, for which Google currently does not have a default parser to normalize data according to the udm standard. I will make this custom integration through the deployment of a cloud function.

# Pre-requisites
 - Chronicle Ingestion API JSON Developer Service Account
 - your Chronicle SIEM instance region
 - Chronicle Customer GUID
 - CTM API key and Secret


   
