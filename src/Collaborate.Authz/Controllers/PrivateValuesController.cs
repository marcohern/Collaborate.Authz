using Collaborate.Authz.Middleware;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Collaborate.Authz.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [RequireBearerToken]
    public class PrivateValuesController : ControllerBase
    {
        public PrivateValuesController()
        {
        }

        [HttpGet]
        public async Task<List<Tuple<string, object>>> GetValuesAsync()
        {
            await Task.CompletedTask;
            return new List<Tuple<string, object>>
            {
                new Tuple<string, object>("PrivateValue1", "This is a private value 1"),
                new Tuple<string, object>("PrivateValue2", "This is a private value 2"),
                new Tuple<string, object>("PrivateValue3", "This is a private value 3"),
            };
        }
    }
}
