using SafeScribeV2.model;

namespace SafeScribeV2.Dto;

public class UserRegisterDTO
{
    public Role Role { get; set; }
    public string Password { get; set; }
    public string Username { get; set; }
}