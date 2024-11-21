namespace SharedKernal
{
    public sealed class ServiceResult : Result, IServiceResult
    {
        private ServiceResult(Error[] errors)
            : base(false, IServiceResult.ServiceError)
        {
            Errors = errors;
        }
        
        private ServiceResult(Error error)
            : base(false, error)
        {
            Errors = [];
        }
        
        private ServiceResult()
            : base(true, Error.None)
        {
            Errors = [];
        }

        public Error[] Errors { get; }

        public static ServiceResult WithoutErrors() => new();
        public static ServiceResult WithError(Error error) => new();
        public static ServiceResult WithErrors(Error[] errors) => new(errors);

    }

    public sealed class ServiceResult<TValue> : Result<TValue>, IServiceResult
    {
        private ServiceResult(Error[] errors)
            : base(default, false, IServiceResult.ServiceError)
        {
            Errors = errors;
        }
        
        private ServiceResult(Error error)
            : base(default, false, error)
        {
            Errors = [];
        } 
        
        private ServiceResult(TValue value)
            : base(value, true, Error.None)
        {
            Errors = [];
        }

        public Error[] Errors { get; }

        public static ServiceResult<TValue> WithError(Error error) => new(error);
        public static ServiceResult<TValue> WithErrors(Error[] errors) => new(errors);
        public static ServiceResult<TValue> WithoutErrors(TValue value) => new(value);
    }
}
