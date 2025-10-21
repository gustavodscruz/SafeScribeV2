using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SafeScribeV2.Dto;
using SafeScribeV2.model;
using SafeScribeV2.Services;

namespace SafeScribeV2.Controller;

[ApiController]
[Route("[controller]")]
public class NotasController : ControllerBase
{
    private readonly TokenService _tokenService;

    public static List<Note> notas = [];

    public NotasController(TokenService tokenService)
    {
        _tokenService = tokenService;
    }

    /// <summary>
    /// Cria uma nova nota associada ao usuário autenticado.
    /// </summary>
    /// <param name="dto">DTO com título e conteúdo da nota.</param>
    /// <returns>200 com a nota criada ou 400/401 em caso de erro.</returns>
    [Authorize(Roles = "Editor, Admin")]
    [HttpPost]
    public IActionResult CriarNota([FromBody] NoteCreateDTO dto)
    {
        try
        {
            var username = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                           ?? User.Identity.Name;

            if (string.IsNullOrEmpty(username)) return Unauthorized();

            var nextId = notas.Any() ? notas.Max(n => n.Id) + 1 : 1;

            var note = new Note
            {
                Id = nextId,
                UserId = AuthController.users.FindLast(user => user.Id == AuthController.users.Count() - 1).Id + 1,
                Title = dto.Title,
                Content = dto.Content,
                CreatedAt = DateTime.UtcNow
            };

            notas.Add(note);

            return Ok(note);
        }
        catch (Exception e)
        {
            return BadRequest("Nota não pode ser criada");
        }
    }

    /// <summary>
    /// Obtém uma nota pelo id. Admins podem acessar qualquer nota; usuários comuns apenas as próprias.
    /// </summary>
    /// <param name="id">Id da nota.</param>
    /// <returns>200 com a nota ou 400/404 em caso de erro/acesso negado.</returns>
    [HttpGet("/{id}")]
    [Authorize]
    public IActionResult ObterNota(int id)
    {
        try
        {
            var username = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                           ?? User.Identity.Name;
            var user = AuthController.users.Find(user => user.Username == username);
            if (user.Role == Role.Admin)
            {
                return Ok(notas.Find(nota => nota.Id == id));
            }

            var nota = notas.Find(nota => nota.Id == id && nota.UserId == user.Id);

            if (nota == null)
            {
                return BadRequest("Você não tem acesso à essa nota");
            }

            return Ok(nota);
        }
        catch (Exception e)
        {
            return BadRequest("Você não tem acesso à essa nota");
        }
    }

    /// <summary>
    /// Atualiza uma nota existente. Editors podem atualizar apenas suas próprias notas; Admins qualquer nota.
    /// </summary>
    /// <param name="id">Id da nota a ser atualizada.</param>
    /// <param name="dto">DTO com os novos título e conteúdo.</param>
    /// <returns>200 com a nota atualizada ou 404/401 se não permitido.</returns>
    [HttpPut("/{id}")]
    [Authorize(Roles = "Editor, Admin")]
    public IActionResult AtualizarNota(int id, [FromBody] NoteCreateDTO dto)
    {
        var username = User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                       ?? User.Identity.Name;
        var user = AuthController.users.Find(user => user.Username == username);
        
        Note? nota = null;

        if (user.Role == Role.Editor)
        {
            nota = notas.Find(n => n.Id == id && n.UserId == user.Id);
        }
        else // Admin
        {
            nota = notas.Find(n => n.Id == id);
        }

        if (nota == null) return NotFound("Nota não encontrada");

        nota.Title = dto.Title;
        nota.Content = dto.Content;

        var idx = notas.FindIndex(n => n.Id == id);
        if (idx >= 0) notas[idx] = nota;

        return Ok(nota);
    }
    
    /// <summary>
    /// Exclui uma nota pelo id. Apenas Admins podem excluir notas.
    /// </summary>
    /// <param name="id">Id da nota a ser removida.</param>
    /// <returns>204 se removido; 404 se não encontrado.</returns>
    [HttpDelete("/{id}")]
    [Authorize(Roles = "Admin")]
    public IActionResult DeletarNota(int id)
    {
        var nota = notas.Find(nota => nota.Id == id);
        
        bool noteIsDeleted = notas.Remove(nota);

        if (!noteIsDeleted) return NotFound("Nota não encontrada");

        return NoContent();
    }
}