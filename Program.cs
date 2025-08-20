using Azure;
using Azure.Data.Tables;
using Azure.Storage.Queues;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

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
builder.Services.AddSingleton<IClickLogger, QueueClickLogger>();

var app = builder.Build();

app.MapGet("/health", (ILogger<Program> logger) =>
{
    logger.LogInformation("/health hit!");
    return Results.Ok(new { status = "ok" });
});

app.MapGet("/{code}", async (string code, HttpContext http, IUrlRepository repo, IClickLogger clicker) =>
{
    if (string.IsNullOrWhiteSpace(code)) return Results.NotFound();

    var entity = await repo.GetAsync(code);
    if (entity is null) return Results.NotFound();

    // fire-and-forget click log
    _ = Task.Run(async () =>
    {
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
    });

    return Results.Redirect(entity.OriginalUrl, permanent: true);
})
.WithName("ResolveCode");

app.MapPost("/api/shorten", async (CreateRequest req, HttpContext http, IUrlRepository repo, ICodeGenerator gen, IOptions<AppOptions> appOpts, ILogger<Program> logger) =>
{
    logger.LogInformation("/api/shorten hit!");

    if (req is null || string.IsNullOrWhiteSpace(req.Url)) return Results.BadRequest("url required");

    if (!Uri.TryCreate(req.Url, UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        return Results.BadRequest("invalid url");

    string code = string.IsNullOrWhiteSpace(req.CustomCode) ? gen.Generate() : req.CustomCode.Trim();
    // enforce allowed chars for custom code
    if (!CodeGenerator.IsValid(code)) return Results.BadRequest("invalid code");

    // collision check and insert
    var created = await repo.CreateAsync(code, uri.ToString());
    if (!created) return Results.Conflict("code already exists");

    var baseUrl = appOpts.Value.BaseUrl?.TrimEnd('/') ?? "";
    var shortUrl = $"{http.Request.Scheme}://{http.Request.Host}/{code}";
    logger.LogInformation($"Shortened URL: {shortUrl} for {req.Url}");
    return Results.Ok(new { code, shortUrl });
});

app.Run();

// Models & Options
record CreateRequest(string Url, string? CustomCode);
record UrlEntity(string Code, string OriginalUrl, DateTimeOffset CreatedUtc);

class StorageOptions { public string? ConnectionString { get; set; } public string TableName { get; set; } = "UrlMappings"; }
class QueueOptions { public bool Enabled { get; set; } = false; public string Name { get; set; } = "clicklogs"; }
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

    public TableUrlRepository(IOptions<StorageOptions> opts)
    {
        var o = opts.Value;
        var service = new TableServiceClient(o.ConnectionString);
        _table = service.GetTableClient(o.TableName);
        _table.CreateIfNotExists();
    }

    public async Task<UrlEntity?> GetAsync(string code)
    {
        try
        {
            var resp = await _table.GetEntityAsync<TableEntity>("url", code);
            var e = resp.Value;
            return new UrlEntity(code, e.GetString("OriginalUrl")!, e.GetDateTime("CreatedUtc")!.Value);
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            return null;
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
            await _table.AddEntityAsync(entity);
            return true;
        }
        catch (RequestFailedException ex) when (ex.Status == 409)
        {
            return false;
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

class QueueClickLogger : IClickLogger
{
    private readonly QueueClient? _queue;
    private readonly bool _enabled;

    public QueueClickLogger(IOptions<QueueOptions> opts, IOptions<StorageOptions> storage)
    {
        _enabled = opts.Value.Enabled;
        if (_enabled)
        {
            _queue = new QueueClient(storage.Value.ConnectionString, opts.Value.Name);
            _queue.CreateIfNotExists();
        }
    }

    public async Task LogAsync(ClickLog log)
    {
        if (!_enabled || _queue is null) return;
        var json = JsonSerializer.Serialize(log);
        var bytes = Encoding.UTF8.GetBytes(json);
        var b64 = Convert.ToBase64String(bytes);
        await _queue.SendMessageAsync(b64, timeToLive: TimeSpan.FromDays(30));
    }
}
