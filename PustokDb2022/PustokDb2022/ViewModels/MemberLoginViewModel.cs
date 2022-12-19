using System.ComponentModel.DataAnnotations;

namespace PustokDb2022.ViewModels
{
    public class MemberLoginViewModel
    {
        [MaxLength(30)]
        public string Username { get; set; }
        [MaxLength(20)]
        [DataType(DataType.Password)]
        public string Password { get; set; }    
    }
}
