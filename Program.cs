using Azure;
using Azure.Data.Tables;
using Azure.Storage.Queues;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

// Configure logging for Azure App Service
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddDebug();
builder.Logging.AddApplicationInsights();

// Set minimum log level
builder.Logging.SetMinimumLevel(LogLevel.Information);

builder.Services.Configure<StorageOptions>(builder.Configuration.GetSection("Storage"));
builder.Services.Configure<QueueOptions>(builder.Configuration.GetSection("Queue"));
builder.Services.Configure<AppOptions>(builder.Configuration.GetSection("App"));

// App Insights
var aiConn = builder.Configuration["ApplicationInsights:ConnectionString"];
if (!string.IsNullOrWhiteSpace(aiConn))
{
    builder.Services.AddApplicationInsightsTelemetry(o => o.ConnectionString = aiConn);
}

// Services
builder.Services.AddSingleton<IUrlRepository, TableUrlRepository>();
builder.Services.AddSingleton<ICodeGenerator>(_ => new CodeGenerator(7));
builder.Services.AddSingleton<IClickLogger, StreamClickLogger>();

var app = builder.Build();

// Add request logging middleware
app.Use(async (context, next) =>
{
    var logger = context.RequestServices.GetRequiredService<ILogger<Program>>();
    logger.LogInformation("Request: {Method} {Path}", context.Request.Method, context.Request.Path);
    await next();
});

app.MapGet("/health", (ILogger<Program> logger) =>
{
    logger.LogInformation("Health check endpoint hit");
    return Results.Ok(new { status = "ok", timestamp = DateTimeOffset.UtcNow });
});

app.MapGet("/{code}", async (string code, HttpContext http, IUrlRepository repo, IClickLogger clicker, ILogger<Program> logger) =>
{
    logger.LogInformation("Redirect request for code: {Code}", code);

    if (string.IsNullOrWhiteSpace(code))
    {
        logger.LogWarning("Empty code provided");
        return Results.NotFound();
    }

    var entity = await repo.GetAsync(code);
    if (entity is null)
    {
        logger.LogWarning("Code not found: {Code}", code);
        return Results.NotFound();
    }

    logger.LogInformation("Redirecting {Code} to {Url}", code, entity.OriginalUrl);

    // Much simpler click logging - no Task.Run needed!
    var referer = http.Request.Headers.Referer.ToString();
    var ua = http.Request.Headers.UserAgent.ToString();
    var ip = http.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    var anonIp = SHA256.HashData(Encoding.UTF8.GetBytes(ip));
    var anonIpHex = Convert.ToHexString(anonIp);

    await clicker.LogAsync(new ClickLog
    {
        Code = code,
        TimestampUtc = DateTimeOffset.UtcNow,
        Referrer = referer,
        UserAgent = ua,
        IpHash = anonIpHex
    });

    return Results.Redirect(entity.OriginalUrl, permanent: true);
});

app.MapPost("/api/shorten", async (CreateRequest req, HttpContext http, IUrlRepository repo, ICodeGenerator gen, IOptions<AppOptions> appOpts, ILogger<Program> logger) =>
{
    logger.LogInformation("Shorten API called with URL: {Url}", req?.Url);

    if (req is null || string.IsNullOrWhiteSpace(req.Url))
    {
        logger.LogWarning("Bad request: URL required");
        return Results.BadRequest("url required");
    }

    if (!Uri.TryCreate(req.Url, UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
    {
        logger.LogWarning("Invalid URL provided: {Url}", req.Url);
        return Results.BadRequest("invalid url");
    }

    string code = string.IsNullOrWhiteSpace(req.CustomCode) ? gen.Generate() : req.CustomCode.Trim();
    logger.LogInformation("Generated/using code: {Code}", code);

    // enforce allowed chars for custom code
    if (!CodeGenerator.IsValid(code))
    {
        logger.LogWarning("Invalid code: {Code}", code);
        return Results.BadRequest("invalid code");
    }

    try
    {
        // collision check and insert
        var created = await repo.CreateAsync(code, uri.ToString());
        if (!created)
        {
            logger.LogWarning("Code collision: {Code}", code);
            return Results.Conflict("code already exists");
        }

        var baseUrl = appOpts.Value.BaseUrl?.TrimEnd('/') ?? "";
        var shortUrl = $"{http.Request.Scheme}://{http.Request.Host}/{code}";
        logger.LogInformation("Successfully created short URL: {ShortUrl} -> {OriginalUrl}", shortUrl, req.Url);

        return Results.Ok(new { code, shortUrl });
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Error creating short URL for: {Url}", req.Url);
        return Results.Problem("Internal server error");
    }
});

// Global exception handler
app.Use(async (context, next) =>
{
    try
    {
        await next();
    }
    catch (Exception ex)
    {
        var logger = context.RequestServices.GetRequiredService<ILogger<Program>>();
        logger.LogError(ex, "Unhandled exception occurred");
        throw;
    }
});

app.Run();

// Models & Options
record CreateRequest(string Url, string? CustomCode);
record UrlEntity(string Code, string OriginalUrl, DateTimeOffset CreatedUtc);

class StorageOptions { public string? ConnectionString { get; set; } public string TableName { get; set; } = "UrlMappings"; }
class QueueOptions { public bool Enabled { get; set; } = true; public string Name { get; set; } = "clicklogs"; }
class AppOptions { public string? BaseUrl { get; set; } = ""; }

// Repo
interface IUrlRepository
{
    Task<UrlEntity?> GetAsync(string code);
    Task<bool> CreateAsync(string code, string url);
}

/// <summary>
/// TODO: Will add logic to ensure table is not more than 100 entries to keep costs low for this basic project
/// </summary>
class TableUrlRepository : IUrlRepository
{
    private readonly TableClient _table;
    private readonly ILogger<TableUrlRepository> _logger;

    public TableUrlRepository(IOptions<StorageOptions> opts, ILogger<TableUrlRepository> logger)
    {
        _logger = logger;
        var o = opts.Value;

        _logger.LogInformation("Initializing table repository with connection string: {HasConnectionString}",
            !string.IsNullOrEmpty(o.ConnectionString));

        var service = new TableServiceClient(o.ConnectionString);
        _table = service.GetTableClient(o.TableName);
        _table.CreateIfNotExists();

        _logger.LogInformation("Table client initialized for table: {TableName}", o.TableName);
    }

    public async Task<UrlEntity?> GetAsync(string code)
    {
        try
        {
            _logger.LogDebug("Getting entity for code: {Code}", code);
            var resp = await _table.GetEntityAsync<TableEntity>("url", code);
            var e = resp.Value;
            var entity = new UrlEntity(code, e.GetString("OriginalUrl")!, e.GetDateTime("CreatedUtc")!.Value);
            _logger.LogDebug("Found entity for code: {Code}", code);
            return entity;
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            _logger.LogDebug("Entity not found for code: {Code}", code);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting entity for code: {Code}", code);
            throw;
        }
    }

    public async Task<bool> CreateAsync(string code, string url)
    {
        var entity = new TableEntity("url", code)
        {
            { "OriginalUrl", url },
            { "CreatedUtc", DateTimeOffset.UtcNow }
        };

        try
        {
            _logger.LogDebug("Creating entity for code: {Code}", code);
            await _table.AddEntityAsync(entity);
            _logger.LogInformation("Successfully created entity for code: {Code}", code);
            return true;
        }
        catch (RequestFailedException ex) when (ex.Status == 409)
        {
            _logger.LogWarning("Entity already exists for code: {Code}", code);
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating entity for code: {Code}", code);
            throw;
        }
    }
}

// Code generator
interface ICodeGenerator { string Generate(); }

class CodeGenerator : ICodeGenerator
{
    private static readonly char[] Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".ToCharArray();
    private readonly int _length;
    private static readonly HashSet<char> Allowed = Alphabet.ToHashSet();

    public CodeGenerator(int length) { _length = length; }

    public string Generate()
    {
        var bytes = RandomNumberGenerator.GetBytes(_length);
        var chars = new char[_length];
        for (int i = 0; i < _length; i++)
        {
            chars[i] = Alphabet[bytes[i] % Alphabet.Length];
        }
        return new string(chars);
    }

    public static bool IsValid(string code) => !string.IsNullOrWhiteSpace(code) && code.All(c => Allowed.Contains(c)) && code.Length <= 32;
}

// Click log
record ClickLog
{
    public string Code { get; init; } = default!;
    public DateTimeOffset TimestampUtc { get; init; }
    public string? Referrer { get; init; }
    public string? UserAgent { get; init; }
    public string? IpHash { get; init; }
}

interface IClickLogger { Task LogAsync(ClickLog log); }

class StreamClickLogger : IClickLogger
{
    private readonly ILogger<StreamClickLogger> _logger;

    public StreamClickLogger(ILogger<StreamClickLogger> logger)
    {
        _logger = logger;
    }

    public Task LogAsync(ClickLog log)
    {
        // Just log it as structured data - App Insights will capture it
        _logger.LogInformation("Click tracked for {Code} from {IpHash} via {Referrer} using {UserAgent}",
            log.Code, log.IpHash, log.Referrer ?? "direct", log.UserAgent ?? "unknown");

        return Task.CompletedTask;
    }
}
