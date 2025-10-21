namespace SafeScribeV2.model;

public class User
{
    public int Id { get; set; }
    public string Username { get; set; }
    public string PasswordHash { get; set; }
    public Role Role { get; set; }
}