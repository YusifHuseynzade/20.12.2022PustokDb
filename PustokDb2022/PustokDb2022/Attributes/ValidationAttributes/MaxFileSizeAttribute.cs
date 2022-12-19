using System.ComponentModel.DataAnnotations;

namespace PustokDb2022.Attributes.ValidationAttributes
{
    public class MaxFileSizeAttribute:ValidationAttribute
    {
        int _maxFileSize;
        public MaxFileSizeAttribute(int maxFileSize)
        {
            _maxFileSize = maxFileSize;
        }

        protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
        {
            List<IFormFile> files = new List<IFormFile>();

            if (value is IFormFile)
            {
                var file = value as IFormFile;
                files.Add(file);
            }else if(value is List<IFormFile>)
            {
                files = value as List<IFormFile>;
            }

            if(files != null)
            {
                foreach(var file in files)
                {
                    if (file.Length > _maxFileSize * 1024 * 1024)
                    {
                        return new ValidationResult("File size must be less than " + _maxFileSize + " MB");
                    }
                }
            }
            return ValidationResult.Success;
        }
    }
}
