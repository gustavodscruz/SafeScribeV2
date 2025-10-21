using SafeScribeV2.model;

namespace SafeScribeV2.Services;

public interface ITokenService
{
    public string GenerateToken(User user);
}