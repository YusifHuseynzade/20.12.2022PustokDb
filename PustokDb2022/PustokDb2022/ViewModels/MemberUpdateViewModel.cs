using System.ComponentModel.DataAnnotations;

namespace PustokDb2022.ViewModels
{
    public class MemberUpdateViewModel
    {
        [MaxLength(30)]
        public string Username { get; set; }
        [MaxLength(30)]
        public string Fullname { get; set; }
        [MaxLength(75)]
        public string Email { get; set; }
        [MaxLength(20)]
        [DataType(DataType.Password)]
        public string? CurrentPassword { get; set; }
        [MaxLength(20)]
        [DataType(DataType.Password)]
        public string?Password { get; set; }
        [MaxLength(20)]
        [DataType(DataType.Password)]
        [Compare("Password", ErrorMessage = "Passwords don't match")]
        public string?RepeatPassword { get; set; }
    }
}
