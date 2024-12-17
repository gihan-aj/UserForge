using System;

namespace Domain.Primitives
{
    public interface ISoftDeletable
    {
        bool IsDeleted { get; }
        public DateTime? DeletedOn { get; }
    }
}
