using System;
using auth.Data;
using auth.Data.Dtos;
using auth.Data.Helpers;
using auth.Models;
using Microsoft.AspNetCore.Components.Forms;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace auth.Controllers
{
    [Route("api")]
    [ApiController]
    public class AuthController : Controller
    {
        private readonly IUserRepository _repository;
        private readonly JwtService _jwtService;

        public AuthController(IUserRepository repository, JwtService jwtService)
        {
            _repository = repository;
            _jwtService = jwtService;
        }

        [HttpGet("hello")]
        public IActionResult Hello()
        {
            return Ok("success");
        }


        [HttpPost("addAdmin")]
        public IActionResult Register(RegisterDto dto)
        {
            var temp = _repository.GetByEmail(dto.Email);
            if (temp != null)
            {
                return BadRequest(new {message = "Email already exists"});
            }

            var user = new User
            {
                Name = dto.Name,
                Email = dto.Email,
                Password = BCrypt.Net.BCrypt.HashPassword(dto.Password)
            };
            return Created("success", _repository.Create(user));
        }

        [HttpPost("login")]
        public IActionResult Login(LoginDto dto)
        {
            var user = _repository.GetByEmail(dto.Email);
            if (user == null) return BadRequest(new {message = "Invalid Credentials"});
            if (!BCrypt.Net.BCrypt.Verify(dto.Password, user.Password))
            {
                return BadRequest(new {message = "Invalid Credentials"});
            }
            var jwt = _jwtService.Generate(user.Id);
            Response.Cookies.Append("jwt", jwt, new CookieOptions
            {
                HttpOnly = true
            });
            return Ok(new
            {
                message = "success"
            });
        }

        [HttpGet("user")]
        public new IActionResult User()
        {
            try
            {
                var jwt = Request.Cookies["jwt"];
                var token = _jwtService.Verify(jwt);
                int userId = int.Parse(token.Issuer);
                var user = _repository.GetById(userId);
                return Ok(user);
            }
            catch (Exception e)
            {
                return Unauthorized();
            }
        }

        [HttpPost("logout")]
        public IActionResult Logout()
        {
            Response.Cookies.Delete("jwt");
            return Ok(new
            {
                message = "success"
            });
        }
    }
}