using SafeScribeV2.model;

namespace SafeScribeV2.Dto;

public class LoginRequestDTO
{
    public string? UserName { get; set; }
    public string? Password { get; set; }
}