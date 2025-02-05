using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.OpenApi.Models;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;

namespace RandomPasswordAPI;

/// <summary>
/// Configuração das opções de geração de senha
/// </summary>
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

/// <summary>
/// Representa uma senha gerada e suas características
/// </summary>
public sealed record PasswordResponse
{
    public required string Password { get; init; }
    public required DateTime Timestamp { get; init; }
    public required int Entropy { get; init; }
    public required string Strength { get; init; }
    public required Dictionary<string, int> CharacterAnalysis { get; init; }
}

/// <summary>
/// Serviço responsável pela geração de senhas seguras
/// </summary>
public interface IPasswordGeneratorService
{
    /// <summary>
    /// Gera uma senha aleatória com base nas opções fornecidas
    /// </summary>
    /// <param name="options">Opções de configuração da senha</param>
    /// <returns>Senha gerada e suas características</returns>
    PasswordResponse GeneratePassword(PasswordOptions options);

    /// <summary>
    /// Avalia a força de uma senha existente
    /// </summary>
    /// <param name="password">Senha a ser avaliada</param>
    /// <returns>Análise da senha</returns>
    PasswordResponse AnalyzePassword(string password);
}

public sealed class PasswordGeneratorService : IPasswordGeneratorService
{
    private static readonly char[] UppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray();
    private static readonly char[] LowercaseChars = "abcdefghijklmnopqrstuvwxyz".ToCharArray();
    private static readonly char[] NumberChars = "0123456789".ToCharArray();
    private static readonly char[] SpecialChars = "!@#$%^&*()_+-=[]{}|;:,.<>?".ToCharArray();
    private static readonly char[] SimilarChars = "il1Lo0O".ToCharArray();
    private static readonly char[] AmbiguousChars = "{}[]()/\\'\"`~,;:.<>".ToCharArray();

    public PasswordResponse GeneratePassword(PasswordOptions options)
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

        // Completa o resto da senha com caracteres aleatórios
        while (password.Length < options.Length)
        {
            password.Append(GetRandomChar(availableChars.ToArray(), rng, bytes));
        }

        // Embaralha a senha final
        var finalPassword = new string(password.ToString().OrderBy(_ => GetRandomInt(rng, bytes)).ToArray());
        
        return CreatePasswordResponse(finalPassword);
    }

    public PasswordResponse AnalyzePassword(string password)
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

/// <summary>
/// Controlador para operações relacionadas a senhas
/// </summary>
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

    /// <summary>
    /// Gera uma nova senha aleatória
    /// </summary>
    /// <param name="options">Opções de geração da senha</param>
    /// <returns>Senha gerada e suas características</returns>
    [HttpGet("generate")]
    [ProducesResponseType(typeof(PasswordResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public IActionResult GeneratePassword([FromQuery] PasswordOptions options)
    {
        try
        {
            _logger.LogInformation("Gerando senha com opções: {@Options}", options);
            var response = _passwordGenerator.GeneratePassword(options);
            return Ok(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao gerar senha");
            return BadRequest(new { error = ex.Message });
        }
    }

    /// <summary>
    /// Analisa a força de uma senha existente
    /// </summary>
    /// <param name="password">Senha a ser analisada</param>
    /// <returns>Análise da senha</returns>
    [HttpPost("analyze")]
    [ProducesResponseType(typeof(PasswordResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public IActionResult AnalyzePassword([FromBody] string password)
    {
        try
        {
            _logger.LogInformation("Analisando senha");
            var response = _passwordGenerator.AnalyzePassword(password);
            return Ok(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao analisar senha");
            return BadRequest(new { error = ex.Message });
        }
    }
}

public static class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        ConfigureServices(builder.Services);

        var app = builder.Build();

        ConfigureMiddleware(app);
        ConfigureEndpoints(app);

        app.Run();
    }

    private static void ConfigureServices(IServiceCollection services)
    {
        services.AddControllers();
        services.AddEndpointsApiExplorer();
        services.AddSwaggerGen(c =>
        {
            c.SwaggerDoc("v1", new OpenApiInfo
            {
                Title = "Password Generator API",
                Version = "v1",
                Description = "API para geração e análise de senhas seguras",
                Contact = new OpenApiContact
                {
                    Name = "Suporte",
                    Email = "suporte@passwordapi.com"
                }
            });

            var xmlFile = $"{System.Reflection.Assembly.GetExecutingAssembly().GetName().Name}.xml";
            var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
            c.IncludeXmlComments(xmlPath);
        });

        services.AddScoped<IPasswordGeneratorService, PasswordGeneratorService>();
        
        services.AddCors(options =>
        {
            options.AddPolicy("AllowAll", builder =>
            {
                builder.AllowAnyOrigin()
                       .AllowAnyMethod()
                       .AllowAnyHeader();
            });
        });

        services.AddHealthChecks();
        services.AddResponseCompression();
    }

    private static void ConfigureMiddleware(WebApplication app)
    {
        if (app.Environment.IsDevelopment())
        {
            app.UseSwagger();
            app.UseSwaggerUI();
        }

        app.UseHttpsRedirection();
        app.UseCors("AllowAll");
        app.UseResponseCompression();
        app.UseAuthorization();
    }

    private static void ConfigureEndpoints(WebApplication app)
    {
        app.MapControllers();
        app.MapHealthChecks("/health");
    }
}
