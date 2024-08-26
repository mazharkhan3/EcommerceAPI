using EcommerceAPI.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace EcommerceAPI.Controllers;

// Todo: Remove controller after testing
[Authorize(Roles = "User")]
[ApiController]
[Route("api/test")]
public class TestController : Controller
{
    private readonly UserService _userService;

    public TestController(UserService userService)
    {
        _userService = userService;
    }

    // Todo: currently it returns the user email, change it to return the user id
    public IActionResult Index()
    {
        var userId = _userService.GetUserId();
        return Ok(userId);
    }
}