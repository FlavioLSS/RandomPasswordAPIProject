using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.OpenApi.Models;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;

namespace RandomPasswordAPI;

public sealed record PasswordOptions
{
    public const int MinLength = 8;
    public const int MaxLength = 128;
    public const int DefaultLength = 12;

    [Range(MinLength, MaxLength)]
    public int Length { get; init; } = DefaultLength;
    
    public bool IncludeUppercase { get; init; } = true;
    public bool IncludeLowercase { get; init; } = true;
    public bool IncludeNumbers { get; init; } = true;
    public bool IncludeSpecialChars { get; init; } = true;
    public bool ExcludeSimilarChars { get; init; } = false;
    public bool ExcludeAmbiguousChars { get; init; } = false;
}

// Entidade para armazenar o histórico de senhas
public sealed class PasswordHistory
{
    public int Id { get; set; }
    public required string Password { get; set; }
    public DateTime Timestamp { get; set; }
    public int Entropy { get; set; }
    public required string Strength { get; set; }
    public required string CharacterAnalysis { get; set; }
    public required string GenerationOptions { get; set; }
    public bool IsAnalysisOnly { get; set; }
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
}

public sealed class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
    
    public DbSet<PasswordHistory> PasswordHistories { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<PasswordHistory>()
            .HasIndex(p => p.Timestamp);

        modelBuilder.Entity<PasswordHistory>()
            .Property(p => p.Password)
            .HasMaxLength(128);

        modelBuilder.Entity<PasswordHistory>()
            .Property(p => p.CharacterAnalysis)
            .HasMaxLength(1000);

        modelBuilder.Entity<PasswordHistory>()
            .Property(p => p.GenerationOptions)
            .HasMaxLength(1000);
    }
}

public sealed record PasswordResponse
{
    public required string Password { get; init; }
    public required DateTime Timestamp { get; init; }
    public required int Entropy { get; init; }
    public required string Strength { get; init; }
    public required Dictionary<string, int> CharacterAnalysis { get; init; }
}

public interface IPasswordGeneratorService
{
    Task<PasswordResponse> GeneratePasswordAsync(PasswordOptions options, string? ipAddress = null, string? userAgent = null);
    Task<PasswordResponse> AnalyzePasswordAsync(string password, string? ipAddress = null, string? userAgent = null);
    Task<IEnumerable<PasswordHistory>> GetPasswordHistoryAsync(DateTime? startDate = null, DateTime? endDate = null);
    Task<Dictionary<string, int>> GetPasswordStrengthStatsAsync();
}

public sealed class PasswordGeneratorService : IPasswordGeneratorService
{
    private static readonly char[] UppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray();
    private static readonly char[] LowercaseChars = "abcdefghijklmnopqrstuvwxyz".ToCharArray();
    private static readonly char[] NumberChars = "0123456789".ToCharArray();
    private static readonly char[] SpecialChars = "!@#$%^&*()_+-=[]{}|;:,.<>?".ToCharArray();
    private static readonly char[] SimilarChars = "il1Lo0O".ToCharArray();
    private static readonly char[] AmbiguousChars = "{}[]()/\\'\"`~,;:.<>".ToCharArray();

    private readonly AppDbContext _context;

    public PasswordGeneratorService(AppDbContext context)
    {
        _context = context;
    }

    public async Task<PasswordResponse> GeneratePasswordAsync(PasswordOptions options, string? ipAddress = null, string? userAgent = null)
    {
        var response = GeneratePassword(options);
        
        var history = new PasswordHistory
        {
            Password = response.Password,
            Timestamp = response.Timestamp,
            Entropy = response.Entropy,
            Strength = response.Strength,
            CharacterAnalysis = System.Text.Json.JsonSerializer.Serialize(response.CharacterAnalysis),
            GenerationOptions = System.Text.Json.JsonSerializer.Serialize(options),
            IsAnalysisOnly = false,
            IpAddress = ipAddress,
            UserAgent = userAgent
        };

        await _context.PasswordHistories.AddAsync(history);
        await _context.SaveChangesAsync();

        return response;
    }

    public async Task<PasswordResponse> AnalyzePasswordAsync(string password, string? ipAddress = null, string? userAgent = null)
    {
        var response = AnalyzePassword(password);

        var history = new PasswordHistory
        {
            Password = response.Password,
            Timestamp = response.Timestamp,
            Entropy = response.Entropy,
            Strength = response.Strength,
            CharacterAnalysis = System.Text.Json.JsonSerializer.Serialize(response.CharacterAnalysis),
            GenerationOptions = "{}",
            IsAnalysisOnly = true,
            IpAddress = ipAddress,
            UserAgent = userAgent
        };

        await _context.PasswordHistories.AddAsync(history);
        await _context.SaveChangesAsync();

        return response;
    }

    public async Task<IEnumerable<PasswordHistory>> GetPasswordHistoryAsync(DateTime? startDate = null, DateTime? endDate = null)
    {
        var query = _context.PasswordHistories.AsQueryable();

        if (startDate.HasValue)
            query = query.Where(p => p.Timestamp >= startDate.Value);

        if (endDate.HasValue)
            query = query.Where(p => p.Timestamp <= endDate.Value);

        return await query
            .OrderByDescending(p => p.Timestamp)
            .Take(1000)
            .ToListAsync();
    }

    public async Task<Dictionary<string, int>> GetPasswordStrengthStatsAsync()
    {
        var stats = await _context.PasswordHistories
            .GroupBy(p => p.Strength)
            .Select(g => new { Strength = g.Key, Count = g.Count() })
            .ToListAsync();

        return stats.ToDictionary(x => x.Strength, x => x.Count);
    }

    private PasswordResponse GeneratePassword(PasswordOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var availableChars = new List<char>();
        
        if (options.IncludeUppercase) availableChars.AddRange(UppercaseChars);
        if (options.IncludeLowercase) availableChars.AddRange(LowercaseChars);
        if (options.IncludeNumbers) availableChars.AddRange(NumberChars);
        if (options.IncludeSpecialChars) availableChars.AddRange(SpecialChars);

        if (options.ExcludeSimilarChars)
            availableChars.RemoveAll(c => SimilarChars.Contains(c));
        
        if (options.ExcludeAmbiguousChars)
            availableChars.RemoveAll(c => AmbiguousChars.Contains(c));

        if (!availableChars.Any())
            throw new InvalidOperationException("Nenhum conjunto de caracteres selecionado para gerar a senha.");

        var password = new StringBuilder(options.Length);
        using var rng = RandomNumberGenerator.Create();
        var bytes = new byte[sizeof(int)];

        // Garante que pelo menos um caractere de cada tipo selecionado está presente
        if (options.IncludeUppercase) password.Append(GetRandomChar(UppercaseChars, rng, bytes));
        if (options.IncludeLowercase) password.Append(GetRandomChar(LowercaseChars, rng, bytes));
        if (options.IncludeNumbers) password.Append(GetRandomChar(NumberChars, rng, bytes));
        if (options.IncludeSpecialChars) password.Append(GetRandomChar(SpecialChars, rng, bytes));

        while (password.Length < options.Length)
        {
            password.Append(GetRandomChar(availableChars.ToArray(), rng, bytes));
        }

        var finalPassword = new string(password.ToString().OrderBy(_ => GetRandomInt(rng, bytes)).ToArray());
        return CreatePasswordResponse(finalPassword);
    }

    private PasswordResponse AnalyzePassword(string password)
    {
        ArgumentException.ThrowIfNullOrEmpty(password);
        return CreatePasswordResponse(password);
    }

    private static char GetRandomChar(char[] chars, RandomNumberGenerator rng, byte[] bytes)
    {
        return chars[GetRandomInt(rng, bytes) % chars.Length];
    }

    private static int GetRandomInt(RandomNumberGenerator rng, byte[] bytes)
    {
        rng.GetBytes(bytes);
        return BitConverter.ToInt32(bytes, 0) & int.MaxValue;
    }

    private static PasswordResponse CreatePasswordResponse(string password)
    {
        var analysis = new Dictionary<string, int>
        {
            ["uppercase"] = password.Count(char.IsUpper),
            ["lowercase"] = password.Count(char.IsLower),
            ["numbers"] = password.Count(char.IsDigit),
            ["special"] = password.Count(c => !char.IsLetterOrDigit(c))
        };

        var entropy = CalculateEntropy(password);
        var strength = GetPasswordStrength(entropy);

        return new PasswordResponse
        {
            Password = password,
            Timestamp = DateTime.UtcNow,
            Entropy = entropy,
            Strength = strength,
            CharacterAnalysis = analysis
        };
    }

    private static int CalculateEntropy(string password)
    {
        var charSet = new HashSet<char>(password);
        var poolSize = 0;

        if (charSet.Any(char.IsUpper)) poolSize += 26;
        if (charSet.Any(char.IsLower)) poolSize += 26;
        if (charSet.Any(char.IsDigit)) poolSize += 10;
        if (charSet.Any(c => !char.IsLetterOrDigit(c))) poolSize += 32;

        return (int)(Math.Log2(Math.Pow(poolSize, password.Length)));
    }

    private static string GetPasswordStrength(int entropy) => entropy switch
    {
        < 28 => "Muito Fraca",
        < 36 => "Fraca",
        < 60 => "Média",
        < 128 => "Forte",
        _ => "Muito Forte"
    };
}

[ApiController]
[Route("api/[controller]")]
public sealed class PasswordController : ControllerBase
{
    private readonly IPasswordGeneratorService _passwordGenerator;
    private readonly ILogger<PasswordController> _logger;

    public PasswordController(IPasswordGeneratorService passwordGenerator, ILogger<PasswordController> logger)
    {
        _passwordGenerator = passwordGenerator;
        _logger = logger;
    }

    [HttpGet("generate")]
    [ProducesResponseType(typeof(PasswordResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> GeneratePassword([FromQuery] PasswordOptions options)
    {
        try
        {
            _logger.LogInformation("Gerando senha com opções: {@Options}", options);
            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
            var userAgent = HttpContext.Request.Headers.UserAgent.ToString();
            
            var response = await _passwordGenerator.GeneratePasswordAsync(options, ipAddress, userAgent);
            return Ok(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao gerar senha");
            return BadRequest(new { error = ex.Message });
        }
    }

    [HttpPost("analyze")]
    [ProducesResponseType(typeof(PasswordResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> AnalyzePassword([FromBody] string password)
    {
        try
        {
            _logger.LogInformation("Analisando senha");
            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
            var userAgent = HttpContext.Request.Headers.UserAgent.ToString();
            
            var response = await _passwordGenerator.AnalyzePasswordAsync(password, ipAddress, userAgent);
            return Ok(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao analisar senha");
            return BadRequest(new { error = ex.Message });
        }
    }

    [HttpGet("history")]
    [ProducesResponseType(typeof(IEnumerable<PasswordHistory>), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetPasswordHistory(
        [FromQuery] DateTime? startDate,
        [FromQuery] DateTime? endDate)
    {
        var history = await _passwordGenerator.GetPasswordHistoryAsync(startDate, endDate);
        return Ok(history);
    }

    [HttpGet("stats")]
    [ProducesResponseType(typeof(Dictionary<string, int>), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetPasswordStats()
    {
        var stats = await _passwordGenerator.GetPasswordStrengthStatsAsync();
        return Ok(stats);
    }
}

public static class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        ConfigureServices(builder.Services, builder.Configuration);

        var app = builder.Build();

        ConfigureMiddleware(app);
        ConfigureEndpoints(app);

        // Aplica as migrações do banco de dados
        using (var scope = app.Services.CreateScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            dbContext.Database.Migrate();
        }

        app.Run();
    }

    private static void ConfigureServices(IServiceCollection services, IConfiguration configuration)
    {
        services.AddDbContext<AppDbContext>(options =>
            options.UseSqlServer(
                configuration.GetConnectionString("DefaultConnection"),
                b => b.MigrationsAssembly("RandomPasswordAPI")));

        services.AddControllers();
        services.AddEndpointsApiExplorer();
        services.
