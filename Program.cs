namespace RandomPasswordAPI;

public class Program
{
    public static void Main(string[] args)
    {
        WebApplicationBuilder builder = WebApplication.CreateBuilder(args);
        WebApplication app = builder.Build();

        app.MapGet("/", () =>
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
            Random random = new Random();
            string password = new string(Enumerable.Repeat(chars, 12)
                .Select(s => s[random.Next(s.Length)])
                .ToArray());

            return Results.Ok(new
            {
                password = password,
                timestamp = DateTime.UtcNow
            });
        });

        app.Run("http://localhost:5000");
    }
}
