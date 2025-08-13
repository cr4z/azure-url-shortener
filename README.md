# URL Shortener Microservice

A lightweight URL shortener built with ASP.NET Core on .NET 9. Created with ASP.NET Core Web Application template, without controllers checked to keep it as one focused service for microservice deployment.

Once integrated into Azure, this application will store URLs at a maximum of 100 entries using Azure Table Storage (as the cheapest NoSQL option, compared to CosmosDB) automatically, and later implement basic telemetry with Azure App Insights.

## Setup

1. **Clone the repository**

2. **Install dependencies**
   - Install Azurite globally: `npm install -g azurite`

3. **Run the application**
   - **Visual Studio**: Open the solution and hit F5
   - Or: **CLI**: `dotnet run`

4. **Start Azurite** (required for storage)
   ```bash
   azurite
   ```

## API Endpoints

### Health Check
```bash
curl -s http://localhost:5120/health
```

### Shorten URL
```bash
curl -s -X POST http://localhost:5120/api/shorten \
  -H "Content-Type: application/json" \
  -d "{\"url\":\"https://www.google.com\"}"
```

## Deployment

Azure deployment coming soon using GitHub Actions, similar to my [QR Scanner Service](https://github.com/cr4z/ticket-verification-service).

## Tech Stack

- ASP.NET Core (.NET 9)
- Azure Storage (via Azurite for local development)
