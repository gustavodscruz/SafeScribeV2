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