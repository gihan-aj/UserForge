using System.Collections.Generic;

namespace Application.Common.Requests
{
    public class BulkIdsRequest<T>
    {
        public BulkIdsRequest(IEnumerable<T> ids)
        {
            Ids = ids ?? new List<T>();
        }
        public IEnumerable<T> Ids { get; }
    }
}
