using System.ComponentModel.DataAnnotations;

namespace PustokDb2022.ViewModels
{
    public class MemberRegisterViewModel
    {
        [MaxLength(30)]
        public string UserName { get; set; }
        [MaxLength(30)]
        public string FullName { get; set; }
        [MaxLength(75)]
        public string Email { get; set; }
        [MaxLength(20)]
        [DataType(DataType.Password)]
        public string Password { get; set; }
        [MaxLength(20)]
        [DataType(DataType.Password)]
        [Compare("Password", ErrorMessage ="Password don't match")]
        public string RepeatPassword { get; set; }

    }
}
