namespace Collaborate.Authz.Entities
{
    public class Pet
    {
        public int? Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public string Species { get; set; } = string.Empty;
        public DateTime? BirthDate { get; set; }
    }
}
