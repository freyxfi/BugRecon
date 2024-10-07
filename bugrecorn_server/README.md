# Bug Recon API Documentation

## Overview

The Bug Recon API is a web application built with FastAPI that provides automated reconnaissance capabilities for specified domains. The API performs subdomain enumeration, port scanning, vulnerability scanning, and directory brute-forcing. Additionally, it captures screenshots of the identified subdomains.

## Endpoints

### 1. Reconnaissance Request

**POST** `/bugrecon/`

This endpoint initiates the reconnaissance process for the specified domain.

#### Request Body

```json
{
  "domain": "example.com",
  "recon_depth": "shallow" // Options: "shallow", "medium", "deep"
}
```

- **domain**: The target domain for reconnaissance.
- **recon_depth**: The depth of the reconnaissance, which can be one of the following:
  - `shallow`: Only subdomain enumeration.
  - `medium`: Subdomain enumeration and port scanning.
  - `deep`: Full reconnaissance including subdomain enumeration, port scanning, vulnerability scanning, and directory brute-forcing.

#### Responses

- **200 OK**: Reconnaissance completed successfully.
  - **Response Body**:
    ```json
    {
      "message": "Recon complete for example.com.",
      "report_file": "example.com_report.txt"
    }
    ```

- **400 Bad Request**: If the `recon_depth` is invalid or no subdomains are found.
  - **Response Body**:
    ```json
    {
      "detail": "[!] Invalid recon depth. Choose either 'shallow', 'medium', or 'deep'."
    }
    ```

### 2. Download Report

**GET** `/download-report/{filename}`

This endpoint allows users to download the generated reconnaissance report.

#### Parameters

- **filename**: The name of the report file to download (e.g., `example.com_report.txt`).

#### Responses

- **200 OK**: Returns the requested report file.
- **404 Not Found**: If the report file does not exist.
  - **Response Body**:
    ```json
    {
      "detail": "Report not found"
    }
    ```

### 3. Download Screenshots

**GET** `/download-screenshots/`

This endpoint allows users to download a zip file containing all the screenshots taken during the reconnaissance process.

#### Responses

- **200 OK**: Returns a zip file of the screenshots.
- **404 Not Found**: If no screenshots have been generated.
  - **Response Body**:
    ```json
    {
      "detail": "Screenshots not found"
    }
    ```

## Usage

1. **Start the FastAPI server**:
   Run the application using Uvicorn:
   ```bash
   uvicorn app:app --reload
   ```

2. **Make a POST request to `/bugrecon/`**:
   Use a tool like `curl` or Postman to send a request:
   ```bash
   curl -X POST "http://localhost:8000/bugrecon/" -H "Content-Type: application/json" -d '{"domain": "example.com", "recon_depth": "deep"}'
   ```

3. **Download the report**:
   Once the reconnaissance is complete, use the report filename provided in the response to download the report:
   ```bash
   curl -O "http://localhost:8000/download-report/example.com_report.txt"
   ```

4. **Download screenshots**:
   To download screenshots, simply make a GET request to `/download-screenshots/`:
   ```bash
   curl -O "http://localhost:8000/download-screenshots/"
   ```

## Requirements

- Python 3.x
- FastAPI
- Requests
- Nmap
- FFUF
- Eyewitness

Make sure to have the necessary tools installed on your server or environment where this API will run.
