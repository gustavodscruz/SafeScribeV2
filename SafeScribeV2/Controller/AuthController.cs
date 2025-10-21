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

    /// <summary>
    /// Realiza o login do usuário com usuário e senha.
    /// </summary>
    /// <param name="model">DTO contendo UserName e Password.</param>
    /// <returns>200 com token gerado em caso de sucesso; 400 em caso de erro.</returns>
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

    /// <summary>
    /// Registra um novo usuário (armazenamento em memória).
    /// </summary>
    /// <param name="model">DTO contendo Username, Password e Role.</param>
    /// <returns>200 se o usuário for criado; 400 em caso de erro.</returns>
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
    /// <summary>
    /// Endpoint protegido que retorna dados apenas para usuários autenticados.
    /// </summary>
    /// <returns>Mensagem de boas-vindas com o nome do usuário autenticado.</returns>
    [HttpGet("dados-protegidos")]
    [Authorize]
    public IActionResult GetDadosProtegidos()
    {
        var username = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        return Ok($"Olá {username}! Você pode acessar os dados que foram protegidos do sistema, meus parabéns!");
    }
}