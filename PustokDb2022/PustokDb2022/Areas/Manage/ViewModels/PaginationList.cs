namespace PustokDb2022.Areas.Manage.ViewModels
{
    public class PaginationList<T>:List<T>
    {
        public int PageSize { get; }
        public int TotalPages { get; }
        public int PageIndex { get; }
       


        public PaginationList(List<T> items,int count, int pageIndex,int pageSize)
        {
            this.AddRange(items);
            this.TotalPages = (int)Math.Ceiling(count / (double)pageSize);
            this.PageIndex = pageIndex;
            this.PageSize = pageSize;
        }

        public bool HasNext => PageIndex < TotalPages;
        public bool HasPrevious => PageIndex > 1;

        public static PaginationList<T> Create(IQueryable<T> query,int pageIndex, int pageSize)
        {
            return new PaginationList<T>(
                    query.Skip((pageIndex - 1) * pageSize).Take(pageSize).ToList(),
                    query.Count(),
                    pageIndex,
                    pageSize
                );
        }
    }
}
