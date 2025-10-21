using System.Security.Claims;
using DevOne.Security.Cryptography.BCrypt;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SafeScribeV2.Dto;
using SafeScribeV2.model;
using SafeScribeV2.Services;

namespace SafeScribeV2.Controller;

[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase
{
    private readonly TokenService _tokenService;

    private PasswordHasher<BCryptHelper> _passwordHasher;
    public static List<User> users = [];

    public AuthController(TokenService tokenService, PasswordHasher<BCryptHelper> passwordHasher)
    {
        _tokenService = tokenService;
        _passwordHasher = passwordHasher;
    }

    [HttpPost("login")]
    [AllowAnonymous]
    public IActionResult Login([FromBody] LoginRequestDTO model)
    {
        if (string.IsNullOrWhiteSpace(model.Password) || string.IsNullOrWhiteSpace(model.UserName))
        {
            return BadRequest("Usuário e senha obrigatórios");
        }
        
        var user = users.Find(user =>
            user.PasswordHash == this._passwordHasher.HashPassword(new BCryptHelper(), model.Password) &&
            user.Username == model.UserName);
        
        if (user == null)
        {
            return BadRequest("Usuário ou Senha inválidos");
        }

        var generatedToken = _tokenService.GenerateToken(user);

        return Ok(new { generatedToken });
    }

    [HttpPost("register")]
    [AllowAnonymous]
    public IActionResult Register([FromBody] UserRegisterDTO model)
    {
        if (string.IsNullOrWhiteSpace(model.Password) || string.IsNullOrWhiteSpace(model.Password))
        {
            return BadRequest("Usuário e senha são obrigatórios");
        }

        var user = users.Find(user => user.Username == model.Username);

        if (user != null)
        {
            return BadRequest("Usuário já existe");
        }

        var hashed = this._passwordHasher.HashPassword(new BCryptHelper(), model.Password);
        users.Add(new User { Username = model.Username, PasswordHash = hashed, Role = model.Role });
        return Ok("Usuário salvo com sucesso");
    }

    [HttpGet("dados-protegidos")]
    [Authorize]
    public IActionResult GetDadosProtegidos()
    {
        var username = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        return Ok($"Olá {username}! Você pode acessar os dados que foram protegidos do sistema, meus parabéns!");
    }
}